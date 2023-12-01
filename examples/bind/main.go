package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/osf4/socks5"
)

// Read the BND.ADDR from the reply and handle it
func handle(bind chan net.Addr) {
	// Here you can send the address to the server and so on
	fmt.Println(<-bind)
}

func main() {
	client := socks5.NewClient(":1080")

	bind := make(chan net.Addr)
	go handle(bind)

	conn, err := client.Bind(context.TODO(), ":5000", bind)
	if err != nil {
		log.Fatal(err)
	}

	conn.Close()
}
