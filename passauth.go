package socks5

import (
	"bufio"
	"bytes"
	"context"
	"io"

	"github.com/osf4/socks5/internal/errio"
)

type statusType byte

const (
	subnegotiationVersion = 0x01

	statusOK      statusType = 0x00
	statusFailure statusType = 0x01
)

type PassAuth struct {
	user, pass []byte
}

// PassAuth represents the password authentication method
func NewPassAuth(user, password string) *PassAuth {
	return &PassAuth{
		user: []byte(user),
		pass: []byte(password),
	}
}

func (a *PassAuth) Request(ctx context.Context, c *Conn) error {
	req := &PassRequest{
		uname:  a.user,
		passwd: a.pass,
	}

	err := c.WriteMessage(ctx, req)
	if err != nil {
		return err
	}

	rep := &PassReply{}
	err = c.ReadMessage(ctx, rep)
	if err != nil {
		return err
	}

	if rep.Status != statusOK {
		return ErrProtocol.New("username or password is wrong")
	}

	return nil
}

func (a *PassAuth) Reply(ctx context.Context, c *Conn) error {
	req := &PassRequest{}

	err := c.ReadMessage(ctx, req)
	if err != nil {
		return err
	}

	rep := &PassReply{}
	if !a.validCredentials(a.user, a.pass) {
		rep.Status = statusFailure

		c.WriteMessage(ctx, rep)
	}

	rep.Status = statusOK
	err = c.WriteMessage(ctx, rep)

	return err
}

func (a *PassAuth) Method() authMethod {
	return MethodPassword
}

// True, if uname && passwd == a.user && a.pass
func (a *PassAuth) validCredentials(uname, passwd []byte) bool {
	userValid := bytes.Equal(a.user, uname)
	passValid := bytes.Equal(a.pass, passwd)

	return userValid && passValid
}

type PassRequest struct {
	uname, passwd []byte
}

func (r *PassRequest) Write(wr io.Writer) error {
	w := bufio.NewWriterSize(wr, 3+len(r.uname)+len(r.passwd))
	ulen, plen := byte(len(r.uname)), byte(len(r.passwd))

	w.WriteByte(subnegotiationVersion)

	w.WriteByte(ulen)
	w.Write(r.uname)

	w.WriteByte(plen)
	w.Write(r.passwd)

	err := w.Flush()
	if err != nil {
		return ErrProtocol.Wrap(err, "unable to write the password authentication request")
	}

	return nil
}

func (r *PassRequest) Read(rd io.Reader) error {
	erd := errio.NewReader(rd)
	b := make([]byte, 2)

	erd.Read(b)

	if b[0] != subnegotiationVersion {
		return ErrProtocol.New("subnegotiation version is wrong (%v)", b[0])
	}

	r.uname = make([]byte, b[1])
	erd.Read(r.uname)

	erd.Read(b[:1])

	r.passwd = make([]byte, b[0])
	erd.Read(r.passwd)

	return erd.Wrap(ErrProtocol, "unable to read the password authentication request")
}

type PassReply struct {
	Status statusType
}

func (r *PassReply) Write(wr io.Writer) error {
	_, err := wr.Write([]byte{subnegotiationVersion, byte(r.Status)})
	if err != nil {
		return ErrProtocol.Wrap(err, "unable to write the password authentication reply")
	}

	return nil
}

func (r *PassReply) Read(rd io.Reader) error {
	erd := errio.NewReader(rd)
	b := make([]byte, 2)

	erd.Read(b)
	if b[0] != subnegotiationVersion {
		return ErrProtocol.New("subnegotiation version is wrong (%v)", b[0])
	}

	r.Status = statusType(b[1])
	return erd.Wrap(ErrProtocol, "unable to read the password autnetication reply")
}
