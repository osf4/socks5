package socks5

import "context"

type authMethod byte

const (
	MethodNotRequired  authMethod = 0x00
	MethodPassword     authMethod = 0x02
	MethodNoAcceptable authMethod = 0xFF
)

// Auth represents an authenticator.
//
// NoAuth - no authentication is required.
//
// PassAuth - password authentication.
type Auth interface {
	Request(ctx context.Context, conn *Conn) error // Send the authentication request to the server
	Reply(ctx context.Context, conn *Conn) error   // Read the authentication request from the client

	Method() authMethod // Byte presentation of the authentication method
}
