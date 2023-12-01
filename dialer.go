package socks5

import (
	"context"
	"net"
)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var (
	defaultDialer = &net.Dialer{}
)

type SOCKSDialer struct {
	client *Client
}

func NewSOCKSDialer(c *Client) *SOCKSDialer {
	return &SOCKSDialer{
		client: c,
	}
}

func (d *SOCKSDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *SOCKSDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		panic("context must be non-nil")
	}

	switch network {
	case "tcp":
		return d.client.Connect(ctx, address)

	case "udp":
		udp, err := d.client.UDP(ctx, address)
		if err != nil {
			return nil, err
		}
		udp.Dst = ParseAddr(network, address)

		return udp, nil

	default:
		return nil, ErrProtocol.Wrap(net.UnknownNetworkError(network), "unable to establish connection")
	}
}
