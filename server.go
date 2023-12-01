package socks5

import (
	"context"
	"io"
	"math/rand"
	"net"
	"strconv"
	"time"
)

// Server represents SOCKS5 server
type Server struct {
	Addr      string // The addr the server is listening at
	UDPBuffer int    // Buffer size that is used by UDP connections

	Auth    Auth          // Authentication method
	Dialer  Dialer        // Dialer that is used to make new network connections
	Timeout time.Duration // Timeout during which the server must handle the request. If the timeout is expired, the connection is closed
	Logger  *switchLogger

	listener net.Listener

	// Base context that is used to cancel all the connections on Server.Close()
	ctx    context.Context
	cancel context.CancelFunc
}

// Return a SOCKS5 server with default options that is ready to listen at addr
func NewServer(addr string) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		Addr:      addr,
		Auth:      NoAuth,
		Dialer:    defaultDialer,
		Logger:    &switchLogger{true, defaultLogger()},
		UDPBuffer: maxUDPHeaderLength,

		ctx:    ctx,
		cancel: cancel,
	}
}

// Start the SOCKS5 server listening at addr
func ListenAndServe(addr string) error {
	srv := NewServer(addr)
	return srv.ListenAndServe()
}

// Start the SOCKS5 server listening at srv.Addr
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":1080"
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return srv.Serve(l)
}

// Start the SOCKS5 server listening at l
func (srv *Server) Serve(l net.Listener) error {
	srv.listener = l
	srv.Logger.Infof("The server is listening at %v\n", srv.listener.Addr())

	for {
		c, err := srv.listener.Accept()
		if err != nil {
			return err
		}

		go srv.serve(c)
	}
}

// Close the listener and cancels all the connections
func (srv *Server) Close() error {
	srv.Logger.Infof("The server was closed")

	srv.cancel()
	return srv.listener.Close()
}

// Authenticate the client and handle the request.
func (srv *Server) serve(c net.Conn) {
	client := NewConn(c)

	err := srv.auth(client)
	if err != nil {
		srv.Logger.Errorf("%v\n", err)
		return
	}

	conn, err := srv.handle(client)
	if err != nil {
		srv.Logger.Errorf("%v\n", err)
		return
	}

	cmd, from, to := conn.Request().Cmd, conn.Client().Raw().RemoteAddr(), conn.Request().Dst
	srv.Logger.Infof("[%v] %v <-> %v\n", cmd, from, to)

	conn.Transfer(srv.ctx)
	conn.Close()
}

// Read the request and choose the appropriate handler.
//
// In case of an error the server sends the failure reply with code of the error
func (srv *Server) handle(client *Conn) (conn conn, err error) {
	ctx := context.Background()
	if srv.timeoutEnabled() {
		timeout, cancel := context.WithTimeout(ctx, srv.Timeout)
		defer cancel()

		ctx = timeout
	}

	req := &Request{}
	err = client.ReadMessage(ctx, req)
	if err != nil {
		return nil, err
	}

	switch req.Cmd {
	case CmdConnect:
		conn, err = srv.handleCONNECT(ctx, client, req)

	case CmdBind:
		conn, err = srv.handleBIND(ctx, client, req)

	case CmdUDP:
		conn, err = srv.handleUDP(ctx, client, req)
	}

	if IsSOCKSError(err) {
		e := err.(*Error)
		srv.sendFailReply(ctx, client, e.Code)

		client.Close()
	}

	return conn, err
}

// Handle the CONNECT request and return the connection that is ready to transfer data.
//
// Error is returned, if the server is unreachable
func (srv *Server) handleCONNECT(ctx context.Context, client *Conn, req *Request) (conn, error) {
	server, err := srv.Dialer.DialContext(ctx, "tcp", req.Dst.String())
	if err != nil {
		errctx := makeErrorContext(client, req, RepHostUnreachable)
		return nil, SOCKSError(errctx.Code, errctx)
	}

	rep := &Reply{Rep: RepSucceeded, Bnd: ParseNetAddr(server.LocalAddr())}
	err = client.WriteMessage(ctx, rep)
	if err != nil {
		return nil, err
	}

	return &tcpConn{client, server, req}, nil
}

// Handle the BIND request and return the connection that is ready to transfer data.
//
// Error is returned, if the incoming connection can not be accepted
func (srv *Server) handleBIND(ctx context.Context, client *Conn, req *Request) (conn, error) {
	bind, err := srv.listen(ctx, "tcp", extractPort(req.Dst.String()), true)
	if err != nil {
		errctx := makeErrorContext(client, req, RepServerFailure)
		return nil, SOCKSError(errctx.Code, errctx)
	}

	listener := bind.(net.Listener)
	defer listener.Close()

	// first reply that contains the address that the server is listening at
	rep := &Reply{Rep: RepSucceeded, Bnd: ParseNetAddr(listener.Addr())}
	err = client.WriteMessage(ctx, rep)
	if err != nil {
		return nil, err
	}

	server, err := listener.Accept()
	if err != nil {
		errctx := makeErrorContext(client, req, RepServerFailure)
		return nil, SOCKSError(errctx.Code, errctx)
	}

	// second reply that contains the server remote address
	rep.Bnd = ParseNetAddr(server.RemoteAddr())
	err = client.WriteMessage(ctx, rep)

	return &tcpConn{client, server, req}, err
}

// Handle the UDP ASSOCIATE request and return the connection that is ready to transfer data.
// It binds two UDP connections for incoming and outgoing data.
//
// Error is returned, if the UDP connections can not be binded
func (srv *Server) handleUDP(ctx context.Context, client *Conn, req *Request) (conn, error) {
	bind, err := srv.listen(ctx, "udp", req.Dst.String(), true)
	if err != nil {
		errctx := makeErrorContext(client, req, RepServerFailure)
		return nil, SOCKSError(errctx.Code, errctx)
	}

	outcome := bind.(*net.UDPConn)

	bind, err = srv.listen(ctx, "udp", randomAddress(), false)
	if err != nil {
		errctx := makeErrorContext(client, req, RepServerFailure)
		return nil, SOCKSError(errctx.Code, errctx)
	}

	income := bind.(*net.UDPConn)

	rep := &Reply{Rep: RepSucceeded, Bnd: ParseNetAddr(outcome.LocalAddr())}
	err = client.WriteMessage(ctx, rep)
	if err != nil {
		return nil, err
	}

	return &udpConn{
		Buffer:  srv.UDPBuffer,
		client:  client,
		income:  income,
		outcome: NewUDPConnSize(client.Raw(), outcome, srv.UDPBuffer),
		req:     req,
	}, nil
}

func (srv *Server) EnableLogger() {
	srv.Logger.Enable = true
}

func (srv *Server) DisableLogger() {
	srv.Logger.Enable = false
}

// Send the reply, where r is REP and the BND.ADDR is 0.0.0.0:0
func (srv *Server) sendFailReply(ctx context.Context, c *Conn, r repType) {
	rep := &Reply{r, NilAddr}
	c.WriteMessage(ctx, rep)
}

// Authenticate the client using the appropriate authentication method.
//
// err is returned, if the client does not support the selected authentication method or credentials are wrong
func (srv *Server) auth(client *Conn) error {
	err := Negotiator.Reply(srv.ctx, client, srv.Auth.Method())
	if err != nil {
		return err
	}

	err = srv.Auth.Reply(srv.ctx, client)
	if err != nil {
		return err
	}

	return nil
}

func (srv *Server) timeoutEnabled() bool {
	return srv.Timeout != 0
}

// Bind the listener at addr. If tryRandomPort == true, it tries to bind the listener not at addr, but at a random address
func (srv *Server) listen(ctx context.Context, network, addr string, tryRandomPort bool) (l any, err error) {
	l, err = srv.makeListener(ctx, network, addr)
	if err != nil {
		// second try to bind the port. If it fails, the error is returned
		if tryRandomPort {
			return srv.listen(ctx, network, randomAddress(), false)
		}

		return nil, err
	}

	return l, nil
}

func (srv *Server) makeListener(ctx context.Context, network, addr string) (any, error) {
	var cfg net.ListenConfig

	switch network {
	case "tcp":
		return cfg.Listen(ctx, network, addr)

	case "udp":
		return cfg.ListenPacket(ctx, network, addr)

	default:

		return nil, net.UnknownNetworkError(network)
	}
}

// conn represents the server side of SOCKS5 connection
type conn interface {
	Transfer(ctx context.Context) // Start transfering data between the client and the server
	Close()                       // Close the client and the server connections

	Client() *Conn
	Server() net.Conn

	Request() *Request
}

// tcpConn represents the server side of connections made by CONNECT and BIND methods
type tcpConn struct {
	client *Conn
	server net.Conn

	req *Request
}

func (c *tcpConn) Transfer(ctx context.Context) {
	result := make(chan struct{})

	go c.transferTo(result, c.server, c.client.Raw())
	go c.transferTo(result, c.client.Raw(), c.server)

	select {
	case <-ctx.Done():
	case <-result:
	}
}

func (c *tcpConn) transferTo(result chan struct{}, to io.Writer, from io.Reader) {
	io.Copy(to, from)
	result <- struct{}{}
}

func (c *tcpConn) Close() {
	c.client.Close()
	c.server.Close()
}

func (c *tcpConn) Client() *Conn {
	return c.client
}

func (c *tcpConn) Server() net.Conn {
	return c.server
}

func (c *tcpConn) Request() *Request {
	return c.req
}

// udpConn represents the server side of connections made by UDP ASSOCIATE
type udpConn struct {
	Buffer int

	client *Conn

	outcome *UDPConn     // outgoing UDP headers from the client
	income  *net.UDPConn // incoming UDP packets to the client

	req *Request
}

func (c *udpConn) Transfer(ctx context.Context) {
	result := make(chan struct{})

	go c.transferIncome(result)
	go c.transferOutcome(result)

	select {
	case <-ctx.Done():
	case <-result:
	}
}

func (c *udpConn) transferIncome(result chan struct{}) {
	for {
		header, err := c.outcome.ReadHeader()
		if err != nil {
			break
		}

		_, err = c.income.WriteTo(header.Data, header.Dst.UDP())
		if err != nil {
			break
		}
	}

	result <- struct{}{}
}

func (c *udpConn) transferOutcome(result chan struct{}) {
	b := make([]byte, c.Buffer)

	for {
		n, addr, err := c.income.ReadFrom(b)
		if err != nil {
			break
		}

		_, err = c.outcome.WriteTo(b[:n], addr)
		if err != nil {
			break
		}
	}

	result <- struct{}{}
}

func (c *udpConn) Close() {
	c.income.Close()
	c.outcome.Close()
}

func (c *udpConn) Client() *Conn {
	return c.client
}

func (c *udpConn) Server() net.Conn {
	return nil
}

func (c *udpConn) Request() *Request {
	return c.req
}

// Return an address in format ":port" with random port. Port interval is [2500, 65535]
func randomAddress() string {
	p := rand.Intn(63035) + 2500
	s := strconv.Itoa(p)

	return net.JoinHostPort("", s)
}

// Split the addr to host/port and return the port
func extractPort(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return port
}
