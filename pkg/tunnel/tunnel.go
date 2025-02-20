package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	quic "github.com/123131513/newquic"
	"github.com/google/uuid"
	"github.com/kungze/quic-tun/pkg/classifier"
	"github.com/kungze/quic-tun/pkg/constants"
	"github.com/kungze/quic-tun/pkg/log"
	"golang.org/x/sys/unix"
)

var (
	BlockSizes      map[string][]int // 全局数组，用于记录每个数据块的大小
	BlockSizesMutex sync.RWMutex     // 读写互斥锁，用于保护 BlockSizes
)

// zzh: add deadline for packet
const deadline = 300 * time.Millisecond

type UDPConn struct {
	pc       net.PacketConn
	remote   net.Addr
	dest     net.Addr
	udpconn  *net.UDPConn
	Queue    chan []byte
	closed   bool
	mu       sync.Mutex
	writeMu  sync.Mutex // 新增一个互斥锁用于写入操作
	isServer bool
	conns    map[string]*UDPConn
	connsMu  sync.Mutex // 新增字段
	// zzh: add current port
	port int
}

func NewUDPConn(pc net.PacketConn, remote net.Addr, dest net.Addr, isServer bool, conns map[string]*UDPConn, udpconn *net.UDPConn) *UDPConn {
	return &UDPConn{
		pc:       pc,
		remote:   remote,
		dest:     dest,
		udpconn:  udpconn,
		Queue:    make(chan []byte, 32768),
		closed:   false,
		mu:       sync.Mutex{},
		writeMu:  sync.Mutex{},
		isServer: isServer,
		conns:    conns,
		port:     0,
	}
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	// fmt.Println("UDP read")
	if !c.isServer {
		data, ok := <-c.Queue // 从队列中读取数据
		// fmt.Println("UDP read from queue")
		if !ok {
			return 0, io.EOF // 如果队列已经关闭，返回EOF错误
		}
		// 提取序号（去掉填充部分）
		// sequenceNumber := strings.TrimRight(string(data), "\x00")

		// fmt.Printf("Received packet from %s: %s\n", c.dest, sequenceNumber)
		n = copy(b, data) // 将数据复制到b
		//fmt.Println("client read")
		//fmt.Println(n)
	} else {
		n, _, err := c.pc.ReadFrom(b)
		// fmt.Println("UDP read from pc")
		if err != nil {
			return 0, err
		}
		//fmt.Println("server read")
		//fmt.Println(n)
		return n, nil
	}
	return n, nil
}

func (c *UDPConn) ReadFull(b []byte) (n int, err error) {
	return c.Read(b)
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()         // 在写入操作前锁定
	defer c.writeMu.Unlock() // 在写入操作后解锁
	var newAddr *net.UDPAddr
	// udpConn, ok := c.pc.(*net.UDPConn)
	// if !ok {
	// 	return 0, fmt.Errorf("not a UDP connection")
	// }
	// 提取 IP 地址和给定的端口，创建新的 UDP 地址
	udpAddr, _ := c.dest.(*net.UDPAddr)
	if c.port != 0 {
		newAddr = &net.UDPAddr{
			IP:   udpAddr.IP,
			Port: c.port,
		}
	} else {
		newAddr = udpAddr
	}

	// fmt.Println("newAddr and dest", newAddr.String(), c.dest.String())

	if c.isServer {
		// udpconn, err := dialUDP("udp", c.dest.(*net.UDPAddr), c.remote.(*net.UDPAddr))
		udpconn, err := dialUDP("udp", newAddr, c.remote.(*net.UDPAddr))
		// udpconn, err := dialUDP("udp", &net.UDPAddr{
		// 	IP:   net.ParseIP("10.0.7.2"), // Replace with your source IP
		// 	Port: 5201,                    // Replace with your source port
		// }, c.remote.(*net.UDPAddr))
		// Create a new UDP co //&net.UDPAddr{
		//IP:   net.ParseIP("10.0.7.2"), // Replace with your source IP
		//Port: 6666,                    // Replace with your source port
		//}, addr.(*net.UDPAddr))
		if err != nil {
			panic(err)
		}
		n, err = udpconn.Write(b) //, c.remote.(*net.UDPAddr))

		udpconn.Close()
		return n, err
		// return udpConn.Write(b)
	} else {
		// udpconn, err := dialUDP("udp", c.dest.(*net.UDPAddr), c.remote.(*net.UDPAddr))
		udpconn, err := dialUDP("udp", c.dest.(*net.UDPAddr), newAddr)
		// udpconn, err := dialUDP("udp", &net.UDPAddr{
		// 	IP:   net.ParseIP("10.0.7.2"), // Replace with your source IP
		// 	Port: 5201,                    // Replace with your source port
		// }, c.remote.(*net.UDPAddr))
		// Create a new UDP co //&net.UDPAddr{
		//IP:   net.ParseIP("10.0.7.2"), // Replace with your source IP
		//Port: 6666,                    // Replace with your source port
		//}, addr.(*net.UDPAddr))
		if err != nil {
			panic(err)
		}
		//defer udpconn.Close()

		// fmt.Println(udpconn.LocalAddr().String())
		// fmt.Println(udpconn.RemoteAddr().String())

		// 提取序号（去掉填充部分）
		// sequenceNumber := strings.TrimRight(string(b), "\x00")

		// fmt.Printf("Received packet from %s: %s\n", c.dest, sequenceNumber)
		n, err = udpconn.Write(b) //, c.remote.(*net.UDPAddr))

		udpconn.Close()
		return n, err
		// // 创建一个 socket

		// conn, err := net.Dial("udp", c.remote.String())
		// if err != nil {
		// 	return 0, err
		// }

		// // 获取到底层的 syscall.RawConn
		// rawConn, err := conn.(*net.UDPConn).SyscallConn()
		// if err != nil {
		// 	return 0, err
		// }

		// // 获取文件描述符
		// var fdc int
		// err = rawConn.Control(func(descriptor uintptr) {
		// 	fdc = int(descriptor)
		// })
		// if err != nil {
		// 	log.Fatalf("Failed to retrieve file descriptor: %v", err)
		// }

		// // 设置 IP_TRANSPARENT 选项
		// var sockfd uintptr
		// err = rawConn.Control(func(fd uintptr) {
		// 	sockfd = uintptr(fd)
		// 	err = unix.SetsockoptInt(int(sockfd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		// })
		// if err != nil {
		// 	return 0, err
		// }

		// // 获取 IP 地址和端口号
		// ip := c.remote.(*net.UDPAddr).IP
		// port := c.remote.(*net.UDPAddr).Port

		// src := &net.UDPAddr{
		// 	IP:   net.ParseIP("10.0.7.2"), // Replace with your source IP
		// 	Port: 6666,                    // Replace with your source port
		// }
		// srcip := src.IP
		// srcport := src.Port

		// // 创建一个 syscall.SockaddrInet4
		// sockaddr := &unix.SockaddrInet4{Port: port}
		// copy(sockaddr.Addr[:], ip.To4())

		// srcsockaddr := &unix.SockaddrInet4{Port: srcport}
		// copy(sockaddr.Addr[:], srcip.To4())

		// // 将 sockaddr 转换为字节切片
		// sockaddrBytes := (*[unsafe.Sizeof(*sockaddr)]byte)(unsafe.Pointer(sockaddr))[:unsafe.Sizeof(*sockaddr)]
		// srcsockaddrBytes := (*[unsafe.Sizeof(*srcsockaddr)]byte)(unsafe.Pointer(srcsockaddr))[:unsafe.Sizeof(*srcsockaddr)]

		// srcsockaddrBytes = srcsockaddrBytes
		// // 创建一个足够大的切片来存储 cmsghdr 结构和源地址
		// control := make([]byte, unix.CmsgSpace(net.IPv4len))

		// // 创建一个 cmsghdr 结构
		// cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		// cmsg.Level = unix.IPPROTO_IP
		// cmsg.Type = unix.IP_PKTINFO
		// cmsg.SetLen(unix.CmsgLen(net.IPv4len))

		// // 将源地址复制到 cmsghdr 结构后面
		// copy(control[unix.CmsgLen(0):], srcip.To4())

		// // 创建一个带有源地址和目标地址的 msghdr
		// msg := &unix.Msghdr{
		// 	Name:       &sockaddrBytes[0],
		// 	Namelen:    uint32(len(sockaddrBytes)),
		// 	Iov:        &[]unix.Iovec{{Base: &b[0], Len: uint64(len(b))}}[0],
		// 	Iovlen:     uint64(len(b)),
		// 	Control:    &control[0],
		// 	Controllen: uint64(len(control)),
		// }

		// // 发送数据包
		// // 获取 unix.SO_SNDBUF 套接字选项
		// sndbuf, err := unix.GetsockoptInt(fdc, unix.SOL_SOCKET, unix.SO_SNDBUF)
		// if err != nil {
		// 	log.Fatalf("Failed to get socket option: %v", err)
		// }

		// fmt.Printf("The maximum allowed packet size is: %d bytes\n", sndbuf)
		// fmt.Println("Hello, World!")
		// fmt.Println(len(sockaddrBytes))
		// fmt.Println(len(b))
		// fmt.Println(len(control))
		// _, _, err = unix.Syscall(unix.SYS_SENDMSG, sockfd, uintptr(unsafe.Pointer(msg)), 0)
		// if err != nil {
		// 	return 0, err
		// }

		// return len(b), nil
	}
}

func (c *UDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.Queue)

	// 删除映射中的 UDPConn
	c.connsMu.Lock() // 在操作映射前锁定
	delete(c.conns, c.remote.String())
	c.connsMu.Unlock() // 在操作映射后解锁

	return nil
}

func (c *UDPConn) LocalAddr() net.Addr {
	return c.pc.LocalAddr()
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	return c.pc.SetDeadline(t)
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	return c.pc.SetReadDeadline(t)
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	return c.pc.SetWriteDeadline(t)
}

// zzh: add datagram stream
// DatagramStream wraps DatagramHandler and implements io.Reader and io.Writer.
type DatagramStream struct {
	handler       quic.Session
	readBuf       []byte
	ClientAppAddr string // zzh: add ClientAppAddr
}

// Write sends data as a datagram.
func (s *DatagramStream) Write(p []byte) (int, error) {
	// fmt.Println("datagram write")
	// fmt.Println(s.ClientAppAddr)
	BlockSizesMutex.RLock()
	copyBlockSizes := make([]int, len(BlockSizes[s.ClientAppAddr]))
	copy(copyBlockSizes, BlockSizes[s.ClientAppAddr])
	BlockSizesMutex.RUnlock()

	// fmt.Println("Write packet")
	err := s.handler.SendMessage(s.ClientAppAddr, p, copyBlockSizes)
	// fmt.Println("Write packet end")
	// 提取序号（去掉填充部分）
	// sequenceNumber := strings.TrimRight(string(p), "\x00")

	// fmt.Printf("Write packet from : %s\n", sequenceNumber)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read receives data from a datagram.
func (s *DatagramStream) Read(p []byte) (int, error) {
	// fmt.Println("datagram read")
	receivedData, err := s.handler.ReceiveMessage()
	if err != nil {
		return 0, err
	}

	// 提取序号（去掉填充部分）
	// sequenceNumber := strings.TrimRight(string(receivedData), "\x00")
	// fmt.Printf("Received packet from : %s\n", sequenceNumber)

	// 将接收到的数据复制到传入的缓冲区 p 中
	n := copy(p, receivedData)
	return n, nil
}

type tunnel struct {
	Session            *quic.Session
	Stream             *quic.Stream     `json:"-"`
	Conn               *UDPConn         `json:"-"`
	Hsh                *HandshakeHelper `json:"-"`
	Uuid               uuid.UUID        `json:"uuid"`
	StreamID           quic.StreamID    `json:"streamId"`
	Endpoint           string           `json:"endpoint"`
	ClientAppAddr      string           `json:"clientAppAddr,omitempty"`
	ServerAppAddr      string           `json:"serverAppAddr,omitempty"`
	RemoteEndpointAddr string           `json:"remoteEndpointAddr"`
	CreatedAt          string           `json:"createdAt"`
	ServerTotalBytes   int64            `json:"serverTotalBytes"`
	ClientTotalBytes   int64            `json:"clientTotalBytes"`
	ServerSendRate     string           `json:"serverSendRate"`
	ClientSendRate     string           `json:"clientSendRate"`
	Protocol           string           `json:"protocol"`
	ProtocolProperties any              `json:"protocolProperties"`
	// Used to cache the header data from QUIC stream
	streamCache *classifier.HeaderCache
	// Used to cache the header data from udp socket connection
	connCache *classifier.HeaderCache
	//zzh: Used to QUIC Datagram
	DatagramStream *DatagramStream
}

// Before the tunnel establishment, client endpoint and server endpoint need to
// process handshake steps (client endpoint send token, server endpont parse and verify token)
func (t *tunnel) HandShake(ctx context.Context) bool {
	res, conn := t.Hsh.Handshakefunc(ctx, t.Stream, t.Hsh)
	if conn != nil {
		t.Conn = conn
	}
	return res
}

func (t *tunnel) countTraffic(ctx context.Context, stream2conn, conn2stream <-chan int) {
	var s2cTotal, s2cPreTotal, c2sTotal, c2sPreTotal int64
	var s2cRate, c2sRate float64
	var tmp int
	timeTick := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case tmp = <-stream2conn:
			s2cTotal += int64(tmp)
		case tmp = <-conn2stream:
			c2sTotal += int64(tmp)
		case <-timeTick.C:
			s2cRate = float64((s2cTotal - s2cPreTotal)) / 32768.0
			s2cPreTotal = s2cTotal
			c2sRate = float64((c2sTotal - c2sPreTotal)) / 32768.0
			c2sPreTotal = c2sTotal
		}
		if t.Endpoint == constants.ClientEndpoint {
			t.ServerTotalBytes = s2cTotal
			t.ServerSendRate = fmt.Sprintf("%.2f kB/s", s2cRate)
			t.ClientTotalBytes = c2sTotal
			t.ClientSendRate = fmt.Sprintf("%.2f kB/s", c2sRate)
		}
		if t.Endpoint == constants.ServerEndpoint {
			t.ServerTotalBytes = c2sTotal
			t.ServerSendRate = fmt.Sprintf("%.2f kB/s", c2sRate)
			t.ClientTotalBytes = s2cTotal
			t.ClientSendRate = fmt.Sprintf("%.2f kB/s", s2cRate)
		}
		DataStore.Store(t.Uuid, *t)
	}
}

func (t *tunnel) Establish(ctx context.Context) {
	logger := log.FromContext(ctx)
	var wg sync.WaitGroup
	wg.Add(2)
	var (
		steam2conn  = make(chan int, 32768)
		conn2stream = make(chan int, 32768)
	)
	t.fillProperties(ctx)
	DataStore.Store(t.Uuid, *t)
	go t.conn2Stream(logger, &wg, conn2stream)
	go t.stream2Conn(logger, &wg, steam2conn)
	logger.Info("Tunnel established successful")
	// If the tunnel already prepare to close but the analyze
	// process still is running, we need to cancle it by concle context.
	ctx, cancle := context.WithCancel(ctx)
	defer cancle()
	go t.countTraffic(ctx, steam2conn, conn2stream)
	go t.analyze(ctx)
	wg.Wait()
	DataStore.Delete(t.Uuid)
	logger.Info("Tunnel closed")
}

// zzh: new establish function
func (t *tunnel) Establish_Datagram(ctx context.Context) {
	logger := log.FromContext(ctx)
	var wg sync.WaitGroup
	wg.Add(2)
	var (
		Datagram2conn = make(chan int, 32768)
		conn2Datagram = make(chan int, 32768)
	)
	t.fillProperties(ctx)
	DataStore.Store(t.Uuid, *t)
	go t.conn2Datagram(logger, &wg, conn2Datagram)
	go t.Datagram2Conn(logger, &wg, Datagram2conn)
	logger.Info("Tunnel established successful")
	// If the tunnel already prepare to close but the analyze
	// process still is running, we need to cancle it by concle context.
	ctx, cancle := context.WithCancel(ctx)
	defer cancle()
	go t.countTraffic(ctx, Datagram2conn, conn2Datagram)
	go t.analyze(ctx)
	wg.Wait()
	DataStore.Delete(t.Uuid)
	logger.Info("Tunnel closed")
}

func (t *tunnel) analyze(ctx context.Context) {
	discrs := classifier.LoadDiscriminators()
	var res int
	// We don't know that the number and time the traffic data pass through the tunnel.
	// This means we cannot know what time we can get the enough data in order to we can
	// distinguish the protocol of the traffic that pass through the tunnel. So, we set
	// a time ticker, periodic to analy the header data until has discirminator affirm the
	// traffic or all discirminators deny the traffic.
	timeTick := time.NewTicker(500 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			DataStore.Delete(t.Uuid)
			return
		case <-timeTick.C:
			for protocol, discr := range discrs {
				//  In client endpoint, connCache store client application header data, streamCache
				// store server application header data; In server endpoint, them is inverse.
				if t.Endpoint == constants.ClientEndpoint {
					res = discr.AnalyzeHeader(ctx, &t.connCache.Header, &t.streamCache.Header)
				} else {
					res = discr.AnalyzeHeader(ctx, &t.streamCache.Header, &t.connCache.Header)
				}
				// If the discriminator deny the traffic header, we delete it.
				if res == classifier.DENY {
					delete(discrs, protocol)
				}
				// Once the traffic's protocol was confirmed, we just need remain this discriminator.
				if res == classifier.AFFIRM || res == classifier.INCOMPLETE {
					t.Protocol = protocol
					t.ProtocolProperties = discr.GetProperties(ctx)
					DataStore.Store(t.Uuid, *t)
					break
				}
			}
			// The protocol was affirmed or all discriminators deny it.
			if res == classifier.AFFIRM || len(discrs) == 0 {
				return
			}
		}
	}
}

func (t *tunnel) fillProperties(ctx context.Context) {
	t.StreamID = (*t.Stream).StreamID()
	if t.Endpoint == constants.ClientEndpoint {
		t.ClientAppAddr = (*t.Conn).RemoteAddr().String()
		t.DatagramStream.ClientAppAddr = t.ClientAppAddr
		// fmt.Println("tunnel fillProperties", t.ClientAppAddr)
	}
	if t.Endpoint == constants.ServerEndpoint {
		t.ServerAppAddr = (*t.Conn).RemoteAddr().String()
	}
	t.RemoteEndpointAddr = fmt.Sprint(ctx.Value(constants.CtxRemoteEndpointAddr))
	t.CreatedAt = time.Now().String()
}

func (t *tunnel) stream2Conn(logger log.Logger, wg *sync.WaitGroup, forwardNumChan chan<- int) {
	defer func() {
		(*t.Stream).Close()
		(*t.Conn).Close()
		wg.Done()
	}()
	isc2s := false
	// Cache the first 32768 byte datas, quic-tun will use them to analy the traffic's protocol
	err := t.copyN(io.MultiWriter(t.Conn, t.streamCache), *t.Stream, classifier.HeaderLength, forwardNumChan, isc2s)
	if err == nil {
		err = t.copy(t.Conn, *t.Stream, forwardNumChan, isc2s)
	}
	if err != nil {
		logger.Errorw("Can not forward packet from QUIC stream to TCP/UNIX socket", "error", err.Error())
	}
}

func (t *tunnel) conn2Stream(logger log.Logger, wg *sync.WaitGroup, forwardNumChan chan<- int) {
	defer func() {
		(*t.Stream).Close()
		(*t.Conn).Close()
		wg.Done()
	}()
	isc2s := true
	// Cache the first 32768 byte datas, quic-tun will use them to analy the traffic's protocol
	err := t.copyN(io.MultiWriter(*t.Stream, t.connCache), t.Conn, classifier.HeaderLength, forwardNumChan, isc2s)
	if err == nil {
		err = t.copy(*t.Stream, t.Conn, forwardNumChan, isc2s)
	}
	if err != nil {
		logger.Errorw("Can not forward packet from TCP/UNIX socket to QUIC stream", "error", err.Error())
	}
}

// zzh: new conn2Datagram function
func (t *tunnel) Datagram2Conn(logger log.Logger, wg *sync.WaitGroup, forwardNumChan chan<- int) {
	defer func() {
		(*t.Stream).Close()
		(*t.Conn).Close()
		wg.Done()
	}()
	isc2s := false
	// Cache the first 32768 byte datas, quic-tun will use them to analy the traffic's protocol
	err := t.copyN_datagram(io.MultiWriter(t.Conn, t.streamCache), t.DatagramStream, classifier.HeaderLength, forwardNumChan, isc2s)
	if err == nil {
		err = t.copy_datagram(t.Conn, t.DatagramStream, forwardNumChan, isc2s)
	}
	if err != nil {
		logger.Errorw("Can not forward packet from QUIC Datagram to TCP/UNIX socket", "error", err.Error())
	}
}

func (t *tunnel) conn2Datagram(logger log.Logger, wg *sync.WaitGroup, forwardNumChan chan<- int) {
	defer func() {
		(*t.Stream).Close()
		(*t.Conn).Close()
		wg.Done()
	}()
	isc2s := true
	// Cache the first 32768 byte datas, quic-tun will use them to analy the traffic's protocol
	err := t.copyN_datagram(io.MultiWriter(t.DatagramStream, t.connCache), t.Conn, classifier.HeaderLength, forwardNumChan, isc2s)
	if err == nil {
		err = t.copy_datagram(t.DatagramStream, t.Conn, forwardNumChan, isc2s)
	}
	if err != nil {
		logger.Errorw("Can not forward packet from TCP/UNIX socket to QUIC stream", "error", err.Error())
	}
}

// Rewrite io.CopyN function https://pkg.go.dev/io#CopyN
func (t *tunnel) copyN(dst io.Writer, src io.Reader, n int64, copyNumChan chan<- int, isc2s bool) error {
	return t.copy(dst, io.LimitReader(src, 0), copyNumChan, isc2s)
}

// Rewrite io.Copy function https://pkg.go.dev/io#Copy
func (t *tunnel) copy(dst io.Writer, src io.Reader, nwChan chan<- int, isc2s bool) (err error) {
	size := 32 * 1024
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}
	buf := make([]byte, size)
	qbu := make([]byte, size)
	// var buf []byte
	// if isc2s {
	// 	buf = make([]byte, size)
	// } else {
	// 	buf = make([]byte, 1316)
	// }
	for {
		// 读取数据包的头部信息，获取数据包的长度
		var packetLength uint32
		var er error
		var nr int
		if isc2s {
			arrivetime := (*t.Session).Getdeadlinestatus()
			//fmt.Println("zzh: arriveTime: ", arrivetime)
			for arrivetime >= time.Duration(deadline) {
				fmt.Println(arrivetime, arrivetime)
				fmt.Println("deadline is exceeded")
				nr, er = src.Read(qbu)
				qbu = qbu[:0]
				nr = 0
				arrivetime = (*t.Session).Getdeadlinestatus()
			}
			// for (*t.Session).Getdeadlinestatus() {
			// 	fmt.Println("deadline is exceeded")
			// 	nr, er = src.Read(buf)
			// 	nr = 0
			// 	// return nil
			// }
			nr, er = src.Read(buf)
		} else {
			err := binary.Read(src, binary.BigEndian, &packetLength)
			if err != nil {
				//fmt.Println("Failed to read packet length:", err)
				break
			}
			fmt.Println("read packet length:", packetLength)
			packetData := make([]byte, packetLength)
			fmt.Println("read packet data")
			nr, er = io.ReadFull(src, packetData)
			if er != nil {
				//fmt.Println("Failed to read packet data:", er)
				break
			}
			buf = packetData
		}
		//nr, er := src.Read(buf)
		//nr, er := io.ReadFull(src, buf)
		//fmt.Println("nr")
		//fmt.Println(nr)
		//fmt.Println(buf[0:nr])
		//fmt.Println("nr")
		if isc2s && nr > 0 {
			// Write the length of the message
			err := binary.Write(dst, binary.BigEndian, uint32(nr))
			if err != nil {
				fmt.Println("Failed to write packet length:", err)
				return err
			}
		}
		if nr > 0 {
			//fmt.Println("Write", nr, "bytes")
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			nwChan <- nw
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return err
}

// Rewrite io.CopyN function https://pkg.go.dev/io#CopyN
func (t *tunnel) copyN_datagram(dst io.Writer, src io.Reader, n int64, copyNumChan chan<- int, isc2s bool) error {
	return t.copy_datagram(dst, io.LimitReader(src, 0), copyNumChan, isc2s)
}

// Rewrite io.Copy function https://pkg.go.dev/io#Copy
func (t *tunnel) copy_datagram(dst io.Writer, src io.Reader, nwChan chan<- int, isc2s bool) (err error) {
	size := 32 * 1024
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}
	// buf := make([]byte, size)
	// var buf []byte
	// if isc2s {
	// 	buf = make([]byte, size)
	// } else {
	// 	buf = make([]byte, 1316)
	// }
	for {
		buf := make([]byte, size)
		// 读取数据包的头部信息，获取数据包的长度
		var packetaddr uint32
		var er error
		var nr int
		// 读取数据
		// fmt.Println("Read packet")
		nr, er = src.Read(buf)
		if er != nil {
			// fmt.Println("Failed to read packet:", er, nr, isc2s)
			// return
		} else {
			// fmt.Println("Read packet:", nr, isc2s)
		}

		if !isc2s {
			// 读取前4个字节作为端口号
			if nr >= 4 {
				packetaddr = uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
				// fmt.Println("read packet addr:", packetaddr)
				t.Conn.port = int(packetaddr)
				// 剩余的数据部分
				buf = buf[4:nr]
				nr = len(buf)
			} else {
				fmt.Println("Packet length is less than 4 bytes")
				// return
			}
		}

		// sequenceNumber := strings.TrimRight(string(buf), "\x00")

		// fmt.Printf("s2c packet from : %s\n", sequenceNumber)

		var data []byte
		if isc2s && nr > 0 && string(buf[0:nr]) != constants.BlockEndMarker {
			// 获取远程地址的端口号
			udpAddr, ok := t.Conn.RemoteAddr().(*net.UDPAddr)
			if !ok {
				fmt.Println("unknown address type")
				return
			}
			port := uint32(udpAddr.Port)
			// fmt.Println("read packet port:", port)
			// 将端口号和数据拼接在一起
			data = append([]byte{}, byte(port>>24), byte(port>>16), byte(port>>8), byte(port)) // 4字节的端口号
		}
		data = append(data, buf[:nr]...) // 拼接数据
		nr = len(data)
		if nr > 0 {
			// fmt.Println("Write", nr, "bytes")
			nw, ew := dst.Write(data)
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			nwChan <- nw
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	// fmt.Println("copy_datagram end")
	return err
}

// Rewrite io.Copy function https://pkg.go.dev/io#Copy
func (t *tunnel) copy_datagram_1(dst io.Writer, src io.Reader, nwChan chan<- int, isc2s bool) (err error) {
	size := 32 * 1024
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}
	buf := make([]byte, size)
	blockCount := 0  // 初始化块计数器
	packetCount := 0 // 初始化数据包计数器
	blockSize := 0   // 初始化块大小计数器
	for {
		nr, er := src.Read(buf)
		if !isc2s && nr > 0 {
			// 提取序号（去掉填充部分）
			// sequenceNumber := strings.TrimRight(string(buf), "\x00")

			// fmt.Printf("s2c packet from : %s\n", sequenceNumber)
		}
		// 检查是否是块结束标记
		if string(buf[0:nr]) == constants.BlockEndMarker {
			blockCount++ // 增加块计数器
			// 跳过块结束标记，继续读取下一个数据包
			fmt.Printf("Block end block number: %d, packet count: %d, block size: %d bytes\n", blockCount, packetCount, blockSize)
			// 重置数据包计数器
			packetCount = 0
			blockSize = 0
			// 跳过块结束标记，继续读取下一个数据包
			// continue
		}
		if nr > 0 {
			packetCount++   // 增加数据包计数器
			blockSize += nr // 增加块大小计数器
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			nwChan <- nw
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return err
}

func NewTunnel(session *quic.Session, stream *quic.Stream, endpoint string) tunnel {
	var streamCache = classifier.HeaderCache{}
	var connCache = classifier.HeaderCache{}
	return tunnel{
		Session:     session,
		Uuid:        uuid.New(),
		Stream:      stream,
		Endpoint:    endpoint,
		streamCache: &streamCache,
		connCache:   &connCache,
		// zzh: add DatagramStream
		DatagramStream: &DatagramStream{
			handler: *session,
			readBuf: make([]byte, 1500)},
	}
}

// DialUDP connects to the remote address raddr on the network net,
// which must be "udp", "udp4", or "udp6".  If laddr is not nil, it is
// used as the local address for the connection.
func dialUDP(network string, laddr *net.UDPAddr, raddr *net.UDPAddr) (net.Conn, error) {
	remoteSocketAddress, err := udpAddrToSocketAddr(raddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build destination socket address: %s", err)}
	}

	localSocketAddress, err := udpAddrToSocketAddr(laddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build local socket address: %s", err)}
	}

	fileDescriptor, err := unix.Socket(udpAddrFamily(network, laddr, raddr), unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket open: %s", err)}
	}

	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
	}

	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEADDR: %s", err)}
	}
	if err = unix.SetsockoptInt(fileDescriptor, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEPORT: %s", err)}
	}

	if err = unix.Bind(fileDescriptor, localSocketAddress); err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket bind %v: %s", laddr, err)}
	}

	if err = unix.Connect(fileDescriptor, remoteSocketAddress); err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket connect: %s", err)}
	}

	fdFile := os.NewFile(uintptr(fileDescriptor), fmt.Sprintf("net-udp-dial-%s", raddr.String()))
	defer fdFile.Close()

	remoteConn, err := net.FileConn(fdFile)
	if err != nil {
		unix.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("convert file descriptor to connection: %s", err)}
	}

	return remoteConn, nil
}

// udpAddToSockerAddr will convert a UDPAddr
// into a Sockaddr that may be used when
// connecting and binding sockets
func udpAddrToSocketAddr(addr *net.UDPAddr) (unix.Sockaddr, error) {
	switch {
	case addr.IP.To4() != nil:
		ip := [4]byte{}
		copy(ip[:], addr.IP.To4())

		return &unix.SockaddrInet4{Addr: ip, Port: addr.Port}, nil

	default:
		ip := [16]byte{}
		copy(ip[:], addr.IP.To16())

		zoneID, err := strconv.ParseUint(addr.Zone, 10, 32)
		if err != nil {
			return nil, err
		}

		return &unix.SockaddrInet6{Addr: ip, Port: addr.Port, ZoneId: uint32(zoneID)}, nil
	}
}

// udpAddrFamily will attempt to work
// out the address family based on the
// network and UDP addresses
func udpAddrFamily(net string, laddr, raddr *net.UDPAddr) int {
	switch net[len(net)-1] {
	case '4':
		return unix.AF_INET
	case '6':
		return unix.AF_INET6
	}

	if (laddr == nil || laddr.IP.To4() != nil) &&
		(raddr == nil || laddr.IP.To4() != nil) {
		return unix.AF_INET
	}
	return unix.AF_INET6
}
