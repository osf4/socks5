package socks5

import (
	"context"
	"io"
	"net"
)

// Message represents messages sent between the server and the client (negotiation requests, authentication requests, replies)
type Message interface {
	Write(wr io.Writer) error
	Read(rd io.Reader) error
}

// Conn represents SOCKS5 connection
type Conn struct {
	alive bool     // represents if the connection is closed or not
	raw   net.Conn // raw connection

	CloseOnContextDone bool // close the connection, if <-Context.Done()
}

func NewConn(raw net.Conn) *Conn {
	return &Conn{
		alive: true,
		raw:   raw,

		CloseOnContextDone: true,
	}
}

// messageHandler represents a handler that is used to write or to read the message
type messageHandler func(io.ReadWriter, chan error, Message)

// Send the message to the connection.
// If the context is done, the connection will be closed
func (c *Conn) WriteMessage(ctx context.Context, msg Message) error {
	write := func(c io.ReadWriter, res chan error, msg Message) {
		err := msg.Write(c)
		res <- err
	}

	return c.processMessage(ctx, msg, write)
}

// Read a message from the connection.
// If the context is done, the connection will be closed
func (c *Conn) ReadMessage(ctx context.Context, msg Message) error {
	read := func(c io.ReadWriter, res chan error, msg Message) {
		err := msg.Read(c)
		res <- err
	}

	return c.processMessage(ctx, msg, read)
}

// Calls handler in a goroutine and waits for the result.
//
// err != nil, if the message can not be processed or ctx, c.Context is done
func (c *Conn) processMessage(ctx context.Context, msg Message, handler messageHandler) error {
	if ctx == nil {
		panic("context must be non-nil")
	}

	res := make(chan error)
	go handler(c.raw, res, msg)

	select {
	case <-ctx.Done():
		c.onContextDone()
		return ctx.Err()

	case err := <-res:
		return err
	}
}

// Raw connection
func (c *Conn) Raw() net.Conn {
	return c.raw
}

// Connection is closed or not
func (c *Conn) Alive() bool {
	return c.alive
}

func (c *Conn) Close() error {
	c.alive = false
	return c.raw.Close()
}

func (c *Conn) onContextDone() {
	if c.CloseOnContextDone {
		c.Close()
	}
}
