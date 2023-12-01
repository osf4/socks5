package socks5

import "github.com/joomcode/errorx"

var (
	ErrSOCKS    = errorx.NewNamespace("socks5")
	ErrProtocol = ErrSOCKS.NewType("protocol")
	ErrConn     = ErrSOCKS.NewType("connection")
)

// Error represents a SOCKS5 error
type Error struct {
	Code  repType // code of the error (from 0x01 to 0x08)
	Cause error
}

func (e *Error) Error() string {
	return e.Cause.Error()
}

func IsSOCKSError(err error) bool {
	if err == nil {
		return false
	}

	_, ok := err.(*Error)
	return ok
}

// Make a socks5.Error from reply code and a raw error.
//
// If code == 0, nil is returned
func SOCKSError(code repType, cause error) *Error {
	if code == RepSucceeded {
		return nil
	}

	return &Error{
		Code:  code,
		Cause: cause,
	}
}

// errorContext contains full context about the error
type errorContext struct {
	Conn    *Conn    // connection where the error was occured
	Request *Request // request sent by the client
	Code    repType  // error code
}

func (e *errorContext) Error() string {
	var cause error

	switch e.Code {
	case RepServerFailure:
		cause = ErrProtocol.New("general SOCKS server failure (%v -> %v)", e.Conn.Raw().RemoteAddr(), e.Request.Dst)

	case RepConnNotAllowed:
		cause = ErrProtocol.New("connection is not allowed by ruleset (%v -> %v)", e.Conn.Raw().RemoteAddr(), e.Request.Dst)

	case RepNetworkUnreachable:
		cause = ErrProtocol.New("network '%v' unreachable (%v - > %v)", e.Request.Dst.network, e.Conn.Raw().RemoteAddr(), e.Request.Dst)

	case RepHostUnreachable:
		cause = ErrProtocol.New("host unreachable (%v -> %v)", e.Conn.Raw().RemoteAddr(), e.Request.Dst)

	case RepConnRefused:
		cause = ErrProtocol.New("connection refused (%v -> %v)", e.Conn.Raw().RemoteAddr(), e.Request.Dst)

	case RepTTLExpired:
		cause = ErrProtocol.New("TTL Expired (%v -> %v)", e.Conn.Raw().RemoteAddr(), e.Request.Dst)

	case RepCmdNotSupported:
		cause = ErrProtocol.New("command '%v' is not supported (%v - > %v)", e.Request.Cmd, e.Conn.Raw().RemoteAddr(), e.Request.Dst)

	case RepAddrNotSupported:
		cause = ErrProtocol.New("address type '%v' is not supported (%v -> %v)", e.Request.Dst.Atyp, e.Conn.Raw().RemoteAddr(), e.Request.Dst)

	}

	return cause.Error()
}

func makeErrorContext(conn *Conn, req *Request, code repType) *errorContext {
	return &errorContext{
		Conn:    conn,
		Request: req,
		Code:    code,
	}
}
