package socks5

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"time"

	"github.com/osf4/socks5/internal/errio"
)

const (
	maxUDPHeaderLength = 65535
)

// UDPConn represents a UDP connection
type UDPConn struct {
	control net.Conn // control TCP connection (UDP connection terminates on control.Close)
	data    net.Conn

	income []byte // buffer for incoming headers

	Dst *Addr
}

// Return a UDP connection with default internal buffer size
func NewUDPConn(control, data net.Conn) *UDPConn {
	return NewUDPConnSize(control, data, 0)
}

// Return a UDP connection with custom buffer size
func NewUDPConnSize(control, data net.Conn, buffer int) *UDPConn {
	if buffer == 0 {
		buffer = maxUDPHeaderLength
	}

	c := &UDPConn{
		control: control,
		data:    data,
		income:  make([]byte, buffer),
	}
	go c.onTCPClose()

	return c
}

func (c *UDPConn) Write(p []byte) (n int, err error) {
	if c.Dst == nil {
		return 0, ErrProtocol.New("unable to use UDPConn.Write, cause UDPConn.Dst == nil")
	}

	return c.WriteTo(p, c.Dst)
}

func (c *UDPConn) Read(p []byte) (n int, err error) {
	n, _, err = c.ReadFrom(p)
	return n, err
}

func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	header := &UDPHeader{
		Frag: 0x00,
		Dst:  ParseNetAddr(addr),
		Data: p,
	}

	err = header.Write(c.data)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *UDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	header, err := c.ReadHeader()
	if err != nil {
		return 0, nil, err
	}

	return len(header.Data), header.Dst, nil
}

func (c *UDPConn) ReadHeader() (*UDPHeader, error) {
	n, err := c.data.Read(c.income)
	if err != nil {
		return nil, err
	}

	payload := c.income[:n]
	header := &UDPHeader{}

	err = header.Read(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	return header, nil
}

func (c *UDPConn) LocalAddr() net.Addr {
	return c.data.LocalAddr()
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.Dst
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	return c.data.SetDeadline(t)
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	return c.data.SetWriteDeadline(t)
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	return c.data.SetReadDeadline(t)
}

func (c *UDPConn) Close() error {
	c.control.Close()
	return c.data.Close()
}

// Close the UDP connection, when the control TCP connection is closed
func (c *UDPConn) onTCPClose() {
	c.control.Read(nil) // wait till the connection is closed

	c.Close()
}

// UDPHeader represents UDP headers sent between the client and the server
type UDPHeader struct {
	Frag byte
	Dst  *Addr
	Data []byte
}

func (h *UDPHeader) Write(wr io.Writer) error {
	w := bufio.NewWriterSize(wr, 3+h.Dst.Len()+len(h.Data))

	w.Write([]byte{0x00, 0x00, h.Frag})

	err := h.Dst.Write(w)
	if err != nil {
		return ErrProtocol.Wrap(err, "unable to write the UDP header")
	}

	w.Write(h.Data)

	err = w.Flush()
	if err != nil {
		return ErrProtocol.Wrap(err, "unable to write the UDP header")
	}

	return nil
}

func (h *UDPHeader) Read(rd io.Reader) error {
	erd := errio.NewReader(rd)
	b := make([]byte, 3)

	erd.Read(b)
	h.Frag = b[2]

	h.Dst = new(Addr)
	err := h.Dst.Read("udp", erd)
	if err != nil {
		return err
	}

	h.Data, err = io.ReadAll(erd)
	if err != nil {
		return ErrProtocol.New("unable to read the UDP header")
	}

	return nil
}
