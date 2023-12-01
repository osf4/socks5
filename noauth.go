package socks5

import "context"

var (
	NoAuth = &noAuth{} // NoAuth represents no authentication method
)

type noAuth struct {
}

func (a *noAuth) Request(ctx context.Context, conn *Conn) error {
	return nil
}

func (a *noAuth) Reply(ctx context.Context, conn *Conn) error {
	return nil
}

func (a *noAuth) Method() authMethod {
	return MethodNotRequired
}
