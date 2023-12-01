package socks5

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/osf4/socks5/internal/errio"
)

type addrType byte

const (
	AddrIPV4   addrType = 0x01
	AddrIPv6   addrType = 0x04
	AddrDomain addrType = 0x03
)

// Parse socks5.Address from net.Addr
func ParseNetAddr(addr net.Addr) *Addr {
	return ParseAddr(addr.Network(), addr.String())
}

// Parse Addr from a string
func ParseAddr(network, addr string) *Addr {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}

	if host == "" {
		host = "0.0.0.0"
	}

	portUint, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}

	return &Addr{
		network: network,
		Atyp:    parseAtyp(host),
		Host:    host,
		Port:    uint16(portUint),
	}
}

func parseAtyp(host string) addrType {
	ip := net.ParseIP(host)

	switch {
	case ip.To4() != nil:
		return AddrIPV4

	case ip.To16() != nil:
		return AddrIPv6
	}

	return AddrDomain
}

var (
	NilAddr = &Addr{
		network: "tcp",

		Atyp: AddrIPV4,
		Host: "0.0.0.0",
		Port: 0,
	}
)

// Addr represents DST.ADDR and BND.ADDR fields in requests and replies
type Addr struct {
	network string // network of the address ("tcp" or "udp") is used to make Addr compatible with net.Addr

	Atyp addrType // ATYP field
	Host string   // string presentation of the host ("127.0.0.1", "google.com")
	Port uint16   // PORT field
}

func (a *Addr) Write(wr io.Writer) error {
	w := bufio.NewWriterSize(wr, a.Len())

	w.WriteByte(byte(a.Atyp))

	switch a.Atyp {
	case AddrIPV4, AddrIPv6:
		ip := net.ParseIP(a.Host)
		if ip == nil {
			return ErrProtocol.New("invalid ip address (host=%v, atyp = %v)", a.Host, a.Atyp)
		}

		w.Write(ipBytes(ip))

	case AddrDomain:
		domainLen := byte(len(a.Host))

		w.WriteByte(domainLen)
		io.WriteString(w, a.Host)
	}

	binaryPort := make([]byte, binary.Size(a.Port))
	binary.BigEndian.PutUint16(binaryPort, a.Port)

	w.Write(binaryPort)

	return nil
}

func (a *Addr) Read(network string, rd io.Reader) error {
	erd := errio.NewReader(rd)
	a.network = network

	b := make([]byte, 2)
	erd.Read(b[:1])
	if err := erd.Error(); err != nil {
		return err
	}

	a.Atyp = addrType(b[0])

	switch a.Atyp {
	case AddrIPV4, AddrIPv6:
		i := make([]byte, ipLength(a.Atyp))
		erd.Read(i)

		a.Host = net.IP(i).String()

	case AddrDomain:
		// read the domain length
		erd.Read(b[:1])

		bytesHost := make([]byte, b[0])
		erd.Read(bytesHost)

		a.Host = string(bytesHost)

	default:
		return SOCKSError(RepAddrNotSupported, ErrProtocol.New("unknown address type (%v)", a.Atyp))
	}

	binaryPort := make([]byte, binary.Size(a.Port))
	erd.Read(binaryPort)

	a.Port = binary.BigEndian.Uint16(binaryPort)

	return erd.Wrap(ErrProtocol, "unable to read the address")
}

func (a *Addr) Network() string {
	return a.network
}

func (a *Addr) String() string {
	stringPort := strconv.FormatUint(uint64(a.Port), 10)
	return net.JoinHostPort(a.Host, stringPort)
}

func (a *Addr) Len() int {
	if a.Atyp == AddrDomain {
		return 1 + 1 + len(a.Host) + 2
	}

	return 1 + ipLength(a.Atyp) + 2

}

// UDP version of the address
func (a *Addr) UDP() net.Addr {
	return &net.UDPAddr{
		IP:   net.ParseIP(a.Host),
		Port: int(a.Port),
	}
}

// Length of the IP address (4 for IPv4, 16 for IPv6).
// Return 0, if version is not an IP address
func ipLength(version addrType) int {
	switch version {
	case AddrIPV4:
		return net.IPv4len

	case AddrIPv6:
		return net.IPv6len
	}

	return 0
}

// Bytes of the IP address without 0-bytes.
// If ip is not an IPv4 or IPv6 address, nil is returned
func ipBytes(ip net.IP) []byte {
	switch {
	case ip.To4() != nil:
		// net.IP contains IPv4 addresses in 4 last bytes
		return ip[12:]

	case ip.To16() != nil:
		return ip
	}

	return nil
}
