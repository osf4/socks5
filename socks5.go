package socks5

const Version = 0x05

func isSOCKS5(ver byte) bool {
	return ver == Version
}
