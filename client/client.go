package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	quic "github.com/123131513/newquic"
	"github.com/kungze/quic-tun/pkg/constants"
	"github.com/kungze/quic-tun/pkg/log"
	"github.com/kungze/quic-tun/pkg/token"
	"github.com/kungze/quic-tun/pkg/tunnel"
)

// zzh: 为什么要引入这个包？
var (
	conns              = make(map[string]*(tunnel.UDPConn)) // 声明并初始化conns映射
	mu                 = &sync.Mutex{}                      // 声明并初始化互斥锁
	resetScheduledFlag atomic.Bool                          // 新增原子标记
)

type ClientEndpoint struct {
	LocalSocket          string
	ServerEndpointSocket string
	TokenSource          token.TokenSourcePlugin
	TlsConfig            *tls.Config
}

func (c *ClientEndpoint) Start() {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	os.Setenv("PROJECT_HOME_DIR", dir)

	tunnel.BlockSizes = make(map[string][]int)              // 声明并初始化BlockSizes映射
	tunnel.BlockSizesMutex = make(map[string]*sync.RWMutex) // 声明并初始化互斥锁
	// Dial server endpoint
	cfgServer := &quic.Config{
		KeepAlive:   true,
		CreatePaths: true,
		// Scheduler:   "round_robin", // Or any of the above mentioned scheduler
		// Scheduler: "low_latency",
		// Scheduler: "random",
		// Scheduler: "ecf",
		// Scheduler: "blest",
		Scheduler:       "arrive_time",
		WeightsFile:     dir,
		Training:        false,
		EnableDatagrams: true,
	}
	session, err := quic.DialAddr(c.ServerEndpointSocket, c.TlsConfig, cfgServer) //&quic.Config{KeepAlive: true})
	if err != nil {
		panic(err)
	}
	parent_ctx := context.WithValue(context.TODO(), constants.CtxRemoteEndpointAddr, session.RemoteAddr().String())
	// Listen on a UDP socket, wait client application's connection request.
	localSocket := strings.Split(c.LocalSocket, ":")
	listener, err := net.ListenPacket(strings.ToLower(localSocket[0]), strings.Join(localSocket[1:], ":"))
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	// Type assert to *net.UDPConn
	udpConn := listener.(*net.UDPConn)

	// Get the syscall.RawConn from the *net.UDPConn
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		panic(err)
	}

	// Set the socket option
	err = rawConn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	})
	if err != nil {
		panic(err)
	}

	err = rawConn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if err != nil {
		panic(err)
	}

	err = rawConn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		panic(err)
	}

	err = rawConn.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
	})
	if err != nil {
		panic(err)
	}

	log.Infow("Client endpoint start up successful", "listen address", listener.LocalAddr().String())

	buffer := make([]byte, 65507)

	firstPacketTime := make(map[string]time.Time)
	firstPacketReceived := make(map[string]bool)

	// 创建或打开日志文件
	logFile, err := os.OpenFile("packet_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()

	// 状态机状态
	const (
		State1         = constants.State1
		State2         = constants.State2
		BlockEndMarker = constants.BlockEndMarker
	)
	// 定义计时器超时时间
	const timeoutDuration = 1 * time.Millisecond
	timer := make(map[string]*time.Timer)

	// state := State2
	state := make(map[string]int)
	lastPacketTime := make(map[string]time.Time)
	currentTime := make(map[string]time.Time)
	arrivalTime := make(map[string]int)
	blockNumber := make(map[string]int)
	currentBlockSize := make(map[string]int)
	timeoutChan := make(chan func())

	// 启动一个 goroutine 顺序处理超时事件
	go func() {
		for handleTimeout := range timeoutChan {
			handleTimeout()
		}
	}()

	for {
		// fmt.Println(listener.LocalAddr().String())
		// Accept client application connectin request
		oob := make([]byte, 1024)
		dstAddr := &net.UDPAddr{}

		n, oobn, _, addr, err := udpConn.ReadMsgUDP(buffer, oob)
		// sequenceNumber := strings.TrimRight(string(buffer), "\x00")
		// 定义一个函数来处理计时器超时
		handleTimeout := func() {
			if state[addr.String()] == State2 {
				state[addr.String()] = State1
				// fmt.Println("get conn lock before in handleTimeout")
				mu.Lock()
				defer mu.Unlock()
				// fmt.Println("get conn lock after in handleTimeout")
				conns[addr.String()].Queue <- []byte(BlockEndMarker)
				blockNumber[addr.String()]++
				logEntry := fmt.Sprintf("Timeout: Forced transition to State1 (Block %d) currentBlockSize %d\n", blockNumber[addr.String()], currentBlockSize[addr.String()])
				// BlockSize := currentBlockSize
				// currentBlockSize = 0
				if _, err := logFile.WriteString(logEntry); err != nil {
					panic(err)
				}
				// 记录当前数据块的大小
				// fmt.Println("tunnel.BlockSizesMutex[addr.String()].Lock()")
				tunnel.BlockSizesMutex[addr.String()].Lock()
				// fmt.Println("tunnel.BlockSizesMutex[addr.String()].Lock() done")
				// fmt.Printf("blockNumber: %d and len %d\n", blockNumber[addr.String()], len(tunnel.BlockSizes[addr.String()]))
				tunnel.BlockSizes[addr.String()] = append(tunnel.BlockSizes[addr.String()], 0)
				// fmt.Println("append block size")
				// tunnel.BlockSizes[blockNumber-2] = BlockSize
				tunnel.BlockSizes[addr.String()][blockNumber[addr.String()]-1] = currentBlockSize[addr.String()]
				// fmt.Println("set block size")
				tunnel.BlockSizesMutex[addr.String()].Unlock()
				// fmt.Println("unlock")
				// 重置当前数据块大小
				currentBlockSize[addr.String()] = 0
				// fmt.Println("reset currentBlockSize")
			}
		}

		// fmt.Println("timer before")
		_, flag_time := firstPacketTime[addr.String()]
		// fmt.Println("timer after")
		if !flag_time {
			// fmt.Println("firstPacketTime before")
			firstPacketTime[addr.String()] = time.Now()
			firstPacketReceived[addr.String()] = true
			currentTime[addr.String()] = time.Now()
			arrivalTime[addr.String()] = 0
			timer[addr.String()] = nil
			state[addr.String()] = State2
			lastPacketTime[addr.String()] = currentTime[addr.String()]
			// fmt.Println("firstPacketTime after")
		} else {
			currentTime[addr.String()] = time.Now()
			arrivalTime[addr.String()] = int(currentTime[addr.String()].Sub(firstPacketTime[addr.String()]).Milliseconds())
		}
		// 获取当前时间
		// currentTime := time.Now()
		// if !firstPacketReceived {
		// 	firstPacketTime = currentTime
		// 	firstPacketReceived = true
		// }
		// arrivalTime := currentTime.Sub(firstPacketTime).Milliseconds()
		// logEntry := fmt.Sprintf("Packet received at: %d ms\n", arrivalTime)

		// 状态机逻辑
		switch state[addr.String()] {
		case State1:
			// if currentTime == firstPacketTime || currentTime.Sub(lastPacketTime).Milliseconds() < 1 {
			state[addr.String()] = State2
			lastPacketTime[addr.String()] = currentTime[addr.String()]
			// 重启计时器
			if timer[addr.String()] != nil {
				timer[addr.String()].Stop()
			}
			// 启动计时器
			// timer = time.AfterFunc(timeoutDuration, handleTimeout)
			timer[addr.String()] = time.AfterFunc(timeoutDuration, func() {
				timeoutChan <- handleTimeout
			})
			// } else {
			// 	// 转移到状态1
			// 	state = State1
			// 	blockNumber++
			// 	// 在分块结束时添加标记
			// 	conns[addr.String()].Queue <- []byte(BlockEndMarker)
			// 	// conn.Queue <- []byte(BlockEndMarker)
			// 	lastPacketTime = currentTime
			// }

		case State2:
			if currentTime[addr.String()].Sub(lastPacketTime[addr.String()]).Milliseconds() < 1 {
			}
			// 保持在状态2
			lastPacketTime[addr.String()] = currentTime[addr.String()]
			// 重启计时器
			if timer[addr.String()] != nil {
				timer[addr.String()].Stop()
			}
			// 启动计时器
			// timer = time.AfterFunc(timeoutDuration, handleTimeout)
			// 启动计时器
			timer[addr.String()] = time.AfterFunc(timeoutDuration, func() {
				timeoutChan <- handleTimeout
			})
			// } else {
			// 	// 转移到状态1
			// 	state = State1
			// 	blockNumber++
			// 	// 在分块结束时添加标记
			// 	conns[addr.String()].Queue <- []byte(BlockEndMarker)
			// 	// conn.Queue <- []byte(BlockEndMarker)
			// }
		}

		// 记录数据包
		// logEntry := fmt.Sprintf("Packet received at: %d ms (Block %d, State %d) %s\n", arrivalTime[addr.String()], blockNumber[addr.String()], state[addr.String()], sequenceNumber)
		logEntry := fmt.Sprintf("Packet received at: %d ms (Block %d, State %d) %s\n", arrivalTime[addr.String()], blockNumber[addr.String()], state[addr.String()], addr.String())
		if _, err := logFile.WriteString(logEntry); err != nil {
			panic(err)
		}

		// 更新当前块的大小
		packetSize := n // 假设 packetData 是当前数据包的数据
		_, ok := currentBlockSize[addr.String()]
		if !ok {
			currentBlockSize[addr.String()] = 0
		}
		currentBlockSize[addr.String()] += packetSize

		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			panic(err)
		}
		for _, msg := range msgs {
			if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR {
				originalDstRaw := &unix.RawSockaddrInet4{}
				if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
					panic(err)
				}

				switch originalDstRaw.Family {
				case unix.AF_INET:
					pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(originalDstRaw))
					p := (*[2]byte)(unsafe.Pointer(&pp.Port))
					dstAddr = &net.UDPAddr{
						IP:   net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3]),
						Port: int(p[0])<<8 + int(p[1]),
					}

				case unix.AF_INET6:
					pp := (*unix.RawSockaddrInet6)(unsafe.Pointer(originalDstRaw))
					p := (*[2]byte)(unsafe.Pointer(&pp.Port))
					dstAddr = &net.UDPAddr{
						IP:   net.IP(pp.Addr[:]),
						Port: int(p[0])<<8 + int(p[1]),
						Zone: strconv.Itoa(int(pp.Scope_id)),
					}

				default:
					panic("original destination is an unsupported network family")
				}
				break
			}
		}
		// fmt.Println(dstAddr.String(), addr)
		//n, addr, err := listener.ReadFrom(buffer)
		if err != nil {
			log.Errorw("Client app connect failed", "error", err.Error())
		} else {
			// fmt.Println("get conn lock before in main")
			mu.Lock() // 在访问共享资源前锁定
			// fmt.Println("get conn lock after in main")
			conn, ok := conns[addr.String()]
			if !ok {
				udpconn, err := net.DialUDP("udp", nil, addr) //.(*net.UDPAddr))
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

				udpconn.Close()
				conn = tunnel.NewUDPConn(listener, addr, dstAddr, false, conns, udpConn)
				conns[addr.String()] = conn
				tunnel.BlockSizes[addr.String()] = make([]int, 0)
				tunnel.BlockSizesMutex[addr.String()] = &sync.RWMutex{}
				blockNumber[addr.String()] = 0
				fmt.Println("New connection from", addr.String())
				session.InitConnection(addr.String())
				// 提取序号（去掉填充部分）
				// sequenceNumber := strings.TrimRight(string(buffer[:n]), "\x00")

				// fmt.Printf("Received packet from R%s: %s\n", addr, sequenceNumber)
				// // 正确地将 buffer 拷贝到 Queue 中
				tempBuffer := make([]byte, n)
				copy(tempBuffer, buffer[:n])
				conn.Queue <- tempBuffer
				logger := log.WithValues(constants.ClientAppAddr, addr.String())
				logger.Info("Client connection accepted, prepare to entablish tunnel with server endpint for this connection.")
				go func() {
					defer func() {
						conn.Close()
						logger.Info("Tunnel closed")
					}()
					// Define the number of streams you want to open
					//numStreams := 3
					//for i := 0; i < numStreams; i++ {
					// Open a quic stream for each client application connection.
					stream, err := session.OpenStreamSync()
					if err != nil {
						logger.Errorw("Failed to open stream to server endpoint.", "error", err.Error())
						return
					}
					defer stream.Close()
					logger = logger.WithValues(constants.StreamID, stream.StreamID())
					// Create a context argument for each new tunnel
					ctx := context.WithValue(
						logger.WithContext(parent_ctx),
						constants.CtxClientAppAddr, addr.String())
					hsh := tunnel.NewHandshakeHelper(constants.TokenLength, handshake)
					c.TokenSource = token.NewFixedTokenPlugin("udp:" + dstAddr.String() + ":udp:" + addr.String())
					//hsh.TokenSource = &tokenSource
					hsh.TokenSource = &c.TokenSource
					// Create a new tunnel for the new client application connection.
					tun := tunnel.NewTunnel(&session, &stream, constants.ClientEndpoint)
					tun.Conn = conn
					tun.Hsh = &hsh
					if !tun.HandShake(ctx) {
						return
					}
					tun.Establish_Datagram(ctx)
					//}
				}()
			} else {
				// 提取序号（去掉填充部分）
				// sequenceNumber := strings.TrimRight(string(buffer[:n]), "\x00")

				// fmt.Printf("Received packet from R%s\n", sequenceNumber)
				// 正确地将 buffer 拷贝到 Queue 中
				tempBuffer := make([]byte, n)
				copy(tempBuffer, buffer[:n])
				conn.Queue <- tempBuffer
				// fmt.Printf("Received packet tempBuffer after\n")
			}
			mu.Unlock() // 在访问共享资源后解锁
		}
	}
}

func handshake(ctx context.Context, stream *quic.Stream, hsh *tunnel.HandshakeHelper) (bool, *tunnel.UDPConn) {
	logger := log.FromContext(ctx)
	logger.Info("Starting handshake with server endpoint")
	token, err := (*hsh.TokenSource).GetToken(fmt.Sprint(ctx.Value(constants.CtxClientAppAddr)))
	if err != nil {
		logger.Errorw("Encounter error.", "erros", err.Error())
		return false, nil
	}
	hsh.SetSendData([]byte(token))
	fmt.Println("token:", token)
	_, err = io.CopyN(*stream, hsh, constants.TokenLength)
	if err != nil {
		logger.Errorw("Failed to send token", err.Error())
		return false, nil
	}
	_, err = io.CopyN(hsh, *stream, constants.AckMsgLength)
	if err != nil {
		logger.Errorw("Failed to receive ack", err.Error())
		return false, nil
	}
	switch hsh.ReceiveData[0] {
	case constants.HandshakeSuccess:
		logger.Info("Handshake successful")
		return true, nil
	case constants.ParseTokenError:
		logger.Errorw("handshake error!", "error", "server endpoint can not parser token")
		return false, nil
	case constants.CannotConnServer:
		logger.Errorw("handshake error!", "error", "server endpoint can not connect to server application")
		return false, nil
	default:
		logger.Errorw("handshake error!", "error", "received an unknow ack info")
		return false, nil
	}
}
