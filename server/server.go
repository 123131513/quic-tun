package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

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

type ServerEndpoint struct {
	Address     string
	TlsConfig   *tls.Config
	TokenParser token.TokenParserPlugin
}

func (s *ServerEndpoint) Start() {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	os.Setenv("PROJECT_HOME_DIR", dir)
	// Listen a quic(UDP) socket.
	cfgServer := &quic.Config{
		KeepAlive:   true,
		CreatePaths: true,
		// Scheduler:   "round_robin", // Or any of the above mentioned scheduler
		//Scheduler:   "arrive_time",
		WeightsFile: dir,
		Training:    false,
	}
	listener, err := quic.ListenAddr(s.Address, s.TlsConfig, cfgServer)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	log.Infow("Server endpoint start up successful", "listen address", listener.Addr())
	for {
		// Wait client endpoint connection request.
		session, err := listener.Accept()
		if err != nil {
			log.Errorw("Encounter error when accept a connection.", "error", err.Error())
		} else {
			parent_ctx := context.WithValue(context.TODO(), constants.CtxRemoteEndpointAddr, session.RemoteAddr().String())
			logger := log.WithValues(constants.ClientEndpointAddr, session.RemoteAddr().String())
			logger.Info("A new client endpoint connect request accepted.")
			go func() {
				for {
					// Wait client endpoint open a stream (A new steam means a new tunnel)
					stream, err := session.AcceptStream()
					if err != nil {
						logger.Errorw("Cannot accept a new stream.", "error", err.Error())
						break
					}
					logger := logger.WithValues(constants.StreamID, stream.StreamID())
					ctx := logger.WithContext(parent_ctx)
					hsh := tunnel.NewHandshakeHelper(constants.AckMsgLength, handshake)
					hsh.TokenParser = &s.TokenParser

					tun := tunnel.NewTunnel(&session, &stream, constants.ServerEndpoint)
					tun.Hsh = &hsh
					if !tun.HandShake(ctx) {
						continue
					}
					// After handshake successful the server application's address is established we can add it to log
					ctx = logger.WithValues(constants.ServerAppAddr, (*tun.Conn).RemoteAddr().String()).WithContext(ctx)
					go tun.Establish(ctx)
				}
			}()
		}
	}
}

func handshake(ctx context.Context, stream *quic.Stream, hsh *tunnel.HandshakeHelper) (bool, *tunnel.UDPConn) {
	logger := log.FromContext(ctx)
	logger.Info("Starting handshake with client endpoint")
	if _, err := io.CopyN(hsh, *stream, constants.TokenLength); err != nil {
		logger.Errorw("Can not receive token", "error", err.Error())
		return false, nil
	}
	addr, err := (*hsh.TokenParser).ParseToken(hsh.ReceiveData)
	fmt.Println("addr:", addr)
	if err != nil {
		logger.Errorw("Failed to parse token", "error", err.Error())
		hsh.SetSendData([]byte{constants.ParseTokenError})
		_, _ = io.Copy(*stream, hsh)
		return false, nil
	}
	logger = logger.WithValues(constants.ServerAppAddr, addr)
	logger.Info("starting connect to server app")
	sockets := strings.Split(addr, ":")
	// fmt.Println("sockets:", sockets)
	udpAddr, err := net.ResolveUDPAddr("udp", strings.Join(sockets[1:3], ":"))
	udpdesAddr, err := net.ResolveUDPAddr("udp", strings.Join(sockets[4:], ":"))
	// fmt.Println(strings.Join(sockets[1:3], ":"), strings.Join(sockets[4:], ":"))
	fmt.Println("udpAddr:", udpAddr, "udpdesAddr:", udpdesAddr)
	conn, err := net.DialUDP(strings.ToLower(sockets[0]), nil, udpAddr)
	if err != nil {
		logger.Errorw("Failed to dial server app", "error", err.Error())
		hsh.SetSendData([]byte{constants.CannotConnServer})
		_, _ = io.Copy(*stream, hsh)
		return false, nil
	}
	logger.Info("Server app connect successful")
	hsh.SetSendData([]byte{constants.HandshakeSuccess})
	if _, err = io.CopyN(*stream, hsh, constants.AckMsgLength); err != nil {
		logger.Errorw("Faied to send ack info", "error", err.Error(), "", hsh.SendData)
		return false, nil
	}
	logger.Info("Handshake successful")
	udpConn := tunnel.NewUDPConn(conn, conn.RemoteAddr(), udpdesAddr, true, conns, nil)
	return true, udpConn
}
