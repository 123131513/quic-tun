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
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/kungze/quic-tun/pkg/constants"
	"github.com/kungze/quic-tun/pkg/log"
	"github.com/kungze/quic-tun/pkg/token"
	"github.com/kungze/quic-tun/pkg/tunnel"
	quic "github.com/mutdroco/mpquic_for_video_stream_backend"
)

var (
	conns = make(map[string]*(tunnel.UDPConn)) // 声明并初始化conns映射
	mu    = &sync.Mutex{}                      // 声明并初始化互斥锁
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
	// Dial server endpoint
	cfgServer := &quic.Config{
		KeepAlive:   true,
		CreatePaths: true,
		// Scheduler:   "round_robin", // Or any of the above mentioned scheduler
		// Scheduler: "low_latency",
		// Scheduler: "random",
		// Scheduler: "ecf",
		// Scheduler: "blest",
		Scheduler:   "arrive_time",
		WeightsFile: dir,
		Training:    false,
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

	for {
		// fmt.Println(listener.LocalAddr().String())
		// Accept client application connectin request
		oob := make([]byte, 1024)
		dstAddr := &net.UDPAddr{}

		n, oobn, _, addr, err := udpConn.ReadMsgUDP(buffer, oob)
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
		//fmt.Println(dstAddr.String(), addr)
		//n, addr, err := listener.ReadFrom(buffer)
		if err != nil {
			log.Errorw("Client app connect failed", "error", err.Error())
		} else {
			mu.Lock() // 在访问共享资源前锁定
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
				conn.Queue <- buffer[:n]
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
					tun.Establish(ctx)
					//}
				}()
			} else {
				conn.Queue <- buffer[:n]
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
