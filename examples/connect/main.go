package main

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/osf4/socks5"
)

func main() {
	client := socks5.NewClient(":1080")

	google, err := client.Connect(context.TODO(), "google.com:80")
	if err != nil {
		log.Fatal(err)
	}
	defer google.Close()

	_, err = fmt.Fprintf(google, "GET / HTTP/1.0\r\n\r\n")
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(google)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%q\n", b)
}
