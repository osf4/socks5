package socks5

import (
	"bufio"
	"context"
	"io"

	"github.com/osf4/socks5/internal/errio"
)

var (
	Negotiator = &negotiator{} // Negotiatior allows to send negotiation requests and replies
)

type negotiator struct {
}

// Send the negotiation request to the server.
//
// Error is returned, if the context is done or the server does not support the selected authentication methods
func (n *negotiator) Request(ctx context.Context, c *Conn, methods []authMethod) (authMethod, error) {
	req := &NegotiationRequest{
		Methods: methods,
	}

	err := c.WriteMessage(ctx, req)
	if err != nil {
		return MethodNoAcceptable, ErrProtocol.Wrap(err, "unable to write the negotiation request")
	}

	rep := &NegotiationReply{}
	err = c.ReadMessage(ctx, rep)
	if err != nil {
		return MethodNoAcceptable, ErrProtocol.Wrap(err, "unable to read the negotiation reply")
	}

	if rep.Method == MethodNoAcceptable {
		return MethodNoAcceptable, ErrProtocol.New("neither of selected authentication methods are supported by the server")
	}

	return rep.Method, nil
}

// Send the negotiation reply to the client.
//
// Error is returned, if the context is done
func (n *negotiator) Reply(ctx context.Context, c *Conn, method authMethod) error {
	req := &NegotiationRequest{}
	err := c.ReadMessage(ctx, req)
	if err != nil {
		return err
	}

	rep := &NegotiationReply{}
	if !isMethodSupported(method, req.Methods) {
		rep.Method = MethodNoAcceptable
		c.WriteMessage(ctx, rep)

		return ErrProtocol.New("authentication method (%v) is not supported by the client", method)
	}

	rep.Method = method
	err = c.WriteMessage(ctx, rep)

	return err
}

// True, if methods contains the selected authentication method
func isMethodSupported(method authMethod, methods []authMethod) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}

	return false
}

// NegotationRequest represents negotiation requests sent by the client
type NegotiationRequest struct {
	Methods []authMethod
}

func (r *NegotiationRequest) Write(wr io.Writer) error {
	w := bufio.NewWriterSize(wr, 2+len(r.Methods))

	nmethods := byte(len(r.Methods))
	w.Write([]byte{Version, nmethods})
	w.Write(methods2Bytes(r.Methods))

	err := w.Flush()
	if err != nil {
		return ErrProtocol.Wrap(err, "unable to write the negotation request")
	}

	return nil
}

func (r *NegotiationRequest) Read(rd io.Reader) error {
	erd := errio.NewReader(rd)

	b := make([]byte, 2)
	erd.Read(b)

	if ver := b[0]; !isSOCKS5(ver) {
		return ErrProtocol.New("invalid protocol version (%v)", ver)
	}

	nmethods := b[1]
	methods := make([]byte, nmethods)

	erd.Read(methods)
	r.Methods = bytes2Methods(methods)

	return erd.Wrap(ErrProtocol, "unable to read the negotiation request")
}

// NegotiationReply represents negotiation replies sent by the server
type NegotiationReply struct {
	Method authMethod
}

func (r *NegotiationReply) Write(wr io.Writer) error {
	_, err := wr.Write([]byte{Version, byte(r.Method)})
	if err != nil {
		return ErrProtocol.Wrap(err, "unable to write the negotiation reply")
	}

	return nil
}

func (r *NegotiationReply) Read(rd io.Reader) error {
	b := make([]byte, 2)

	_, err := rd.Read(b)
	if err != nil {
		return ErrProtocol.Wrap(err, "unable to read the negotiation reply")
	}

	if ver := b[0]; !isSOCKS5(ver) {
		return ErrProtocol.New("invalid protocol version (%v)", ver)
	}

	r.Method = authMethod(b[1])
	return nil
}

// Converts a slice of authentication methods to a byte slice
func methods2Bytes(m []authMethod) []byte {
	b := make([]byte, len(m))
	for i := 0; i < len(m); i++ {
		b[i] = byte(m[i])
	}

	return b
}

// Converts a byte slice to a slice of authentication methods
func bytes2Methods(b []byte) []authMethod {
	m := make([]authMethod, len(b))
	for i := 0; i < len(b); i++ {
		m[i] = authMethod(b[i])
	}

	return m
}
