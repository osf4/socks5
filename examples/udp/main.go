package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/osf4/socks5"
)

func read() {
	udp, err := net.ListenPacket("udp", ":8888")
	if err != nil {
		log.Fatal(err)
	}

	b := make([]byte, 15)
	for {
		n, addr, err := udp.ReadFrom(b)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%v -> %q\n", addr, b[:n])
	}
}

func main() {
	client := socks5.NewClient(":1080")
	client.UDPBuffer = 5555

	go read()

	udp, err := client.UDP(context.TODO(), ":5000")
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()

	udp.Dst = socks5.ParseAddr("udp", "127.0.0.1:8888")

	for {
		_, err = io.WriteString(udp, "Hello, world!")
		if err != nil {
			log.Fatal(err)
		}

		time.Sleep(time.Second)
	}
}
