package socks5

import (
	"bufio"
	"io"

	"github.com/osf4/socks5/internal/errio"
)

type cmdType byte

func (c cmdType) String() string {
	switch c {
	case CmdConnect:
		return "CONNECT"

	case CmdBind:
		return "BIND"

	case CmdUDP:
		return "UDP ASSOCIATE"
	}

	return "unknown command"
}

func (c cmdType) Network() string {
	switch c {
	case CmdConnect, CmdBind:
		return "tcp"

	case CmdUDP:
		return "udp"
	}

	return "unknown network"
}

// True, if c is a valid command (CONNECT, BIND or UDP ASSOCIATE)
func (c cmdType) Valid() bool {
	return c < 0x04
}

const (
	CmdConnect cmdType = 0x01
	CmdBind    cmdType = 0x02
	CmdUDP     cmdType = 0x03
)

// Request represents requests sent by the client
type Request struct {
	Cmd cmdType // CMD field
	Dst *Addr   // DST.ADDR field (with ATYP and PORT)
}

func (r *Request) Write(wr io.Writer) error {
	w := bufio.NewWriterSize(wr, 3+r.Dst.Len())

	// VER CMD RSV fields
	w.Write([]byte{Version, byte(r.Cmd), 0x00})

	// ATYP, DST.ADDR, PORT field
	err := r.Dst.Write(w)
	if err != nil {
		return err
	}

	err = w.Flush()
	if err != nil {
		return ErrProtocol.Wrap(err, "unable to write the request")
	}

	return nil
}

func (r *Request) Read(rd io.Reader) error {
	erd := errio.NewReader(rd)

	b := make([]byte, 3)
	erd.Read(b)

	if ver := b[0]; !isSOCKS5(ver) {
		return ErrProtocol.New("invalid protocol version (%v)", ver)
	}

	r.Cmd = cmdType(b[1])
	if !r.Cmd.Valid() {
		return SOCKSError(RepCmdNotSupported, ErrProtocol.New("unknown command (%v)", r.Cmd))
	}

	r.Dst = new(Addr)
	err := r.Dst.Read(r.Cmd.Network(), erd)

	return err
}

type repType byte

// True, if r is a valid reply (RepSucceeded, RepServerFailure...)
func (r repType) Valid() bool {
	return r < 0x09
}

const (
	RepSucceeded          repType = 0x00
	RepServerFailure      repType = 0x01
	RepConnNotAllowed     repType = 0x02
	RepNetworkUnreachable repType = 0x03
	RepHostUnreachable    repType = 0x04
	RepConnRefused        repType = 0x05
	RepTTLExpired         repType = 0x06
	RepCmdNotSupported    repType = 0x07
	RepAddrNotSupported   repType = 0x08
)

// Reply represents replies sent by the server
type Reply struct {
	Rep repType // REP field
	Bnd *Addr   // BND.ADDR field (with ATYP and PORT)
}

func (r *Reply) Write(wr io.Writer) error {
	w := bufio.NewWriterSize(wr, 3+r.Bnd.Len())

	// VER, REP, RSV fields
	w.Write([]byte{Version, byte(r.Rep), 0x00})

	// ATYP, BND.ADDR, PORT fields
	err := r.Bnd.Write(w)
	if err != nil {
		return err
	}

	err = w.Flush()
	if err != nil {
		return ErrProtocol.Wrap(err, "unable to write the reply")
	}

	return nil
}

func (r *Reply) Read(rd io.Reader) error {
	erd := errio.NewReader(rd)

	b := make([]byte, 3)
	erd.Read(b)

	if ver := b[0]; !isSOCKS5(ver) {
		return ErrProtocol.New("invalid protocol version (%v)", ver)
	}

	r.Rep = repType(b[1])
	if !r.Rep.Valid() {
		return ErrProtocol.New("unknown reply code (%v)", r.Rep)
	}

	r.Bnd = new(Addr)
	err := r.Bnd.Read("", erd)

	return err
}
