package socks5

import (
	"context"
	"net"
)

type Client struct {
	Proxy string

	Dialer    Dialer
	Auth      Auth
	UDPBuffer int // Buffer size for UDP headers sent by the server
}

func NewClient(proxy string) *Client {
	return &Client{
		Proxy:  proxy,
		Dialer: defaultDialer,
		Auth:   NoAuth,
	}
}

// Send the CONNECT request
func (c *Client) Connect(ctx context.Context, address string) (net.Conn, error) {
	if ctx == nil {
		panic("context must be non-nil")
	}

	proxy, err := c.proxy(ctx)
	if err != nil {
		return nil, err
	}

	_, _, err = c.cmd(ctx, proxy, CmdConnect, address)
	if err != nil {
		return nil, err
	}

	return proxy.Raw(), nil
}

// Send the BIND request.
//
// bindAddr sends the BND.ADDR from the first reply
func (c *Client) Bind(ctx context.Context, address string, bindAddr chan net.Addr) (net.Conn, error) {
	if ctx == nil {
		panic("context must be non-nil")
	}

	proxy, err := c.proxy(ctx)
	if err != nil {
		return nil, err
	}

	req, rep, err := c.cmd(ctx, proxy, CmdBind, address)
	if err != nil {
		return nil, err
	}

	bindAddr <- rep.Bnd

	_, err = c.readReply(ctx, proxy, req)
	return proxy.Raw(), err
}

func (c *Client) UDP(ctx context.Context, address string) (*UDPConn, error) {
	if ctx == nil {
		panic("context must be non-nil")
	}

	proxy, err := c.proxy(ctx)
	if err != nil {
		return nil, err
	}

	_, rep, err := c.cmd(ctx, proxy, CmdUDP, address)
	if err != nil {
		return nil, err
	}

	control := proxy.Raw() // raw TCP connection to the server
	data, err := net.Dial("udp", rep.Bnd.String())
	if err != nil {
		return nil, ErrProtocol.Wrap(err, "unable to establish the connection to the UDP server")
	}

	return NewUDPConnSize(control, data, c.UDPBuffer), nil
}

// Return a Dialer that will make connections through the proxy server
func (c *Client) SOCKSDialer() Dialer {
	return NewSOCKSDialer(c)
}

// Send a request to the server and reads the reply.
//
// error is returned, if the reply is not RepSucceeded
func (c *Client) cmd(ctx context.Context, proxy *Conn, cmd cmdType, addr string) (*Request, *Reply, error) {
	dst := ParseAddr(cmd.Network(), addr)
	if dst == nil {
		return nil, nil, ErrProtocol.New("unable to parse the address (%v)", addr)
	}

	req := &Request{
		Cmd: cmd,
		Dst: dst,
	}

	err := proxy.WriteMessage(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	rep, err := c.readReply(ctx, proxy, req)
	return req, rep, err
}

// Read the reply from the server.
//
// error is returned, if the reply is not RepSucceeded
func (c *Client) readReply(ctx context.Context, proxy *Conn, req *Request) (*Reply, error) {
	rep := &Reply{}
	err := proxy.ReadMessage(ctx, rep)
	if err != nil {
		return nil, err
	}
	rep.Bnd.network = req.Cmd.Network()

	if rep.Rep != RepSucceeded {
		errctx := makeErrorContext(proxy, req, rep.Rep)
		return nil, SOCKSError(errctx.Code, errctx)
	}

	return rep, nil
}

// Return the authentication SOCKS5 connection to the proxy
func (c *Client) proxy(ctx context.Context) (*Conn, error) {
	raw, err := c.Dialer.DialContext(ctx, "tcp", c.Proxy)
	if err != nil {
		return nil, ErrProtocol.Wrap(err, "unable to establish the connection to the proxy")
	}
	proxy := NewConn(raw)

	method, err := Negotiator.Request(ctx, proxy, c.authMethods())
	if err != nil {
		return nil, err
	}

	auth := c.auth(method)
	err = auth.Request(ctx, proxy)
	if err != nil {
		return nil, err
	}

	return proxy, nil
}

// Return NoAuth method, if method == NoAuth. In other cases c.Auth is returned.
func (c *Client) auth(method authMethod) Auth {
	if method == MethodNotRequired {
		return NoAuth
	}

	return c.Auth
}

func (c *Client) authMethods() []authMethod {
	return []authMethod{MethodNotRequired, c.Auth.Method()}
}
