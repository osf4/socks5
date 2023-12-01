package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/osf4/socks5"
)

func main() {
	client := socks5.NewClient(":1080")
	dialer := client.SOCKSDialer()

	// All HTTP requests will be transmitted through the proxy server
	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
	}

	rep, err := httpClient.Get("http://google.com")
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(rep.Body)
	if err != nil {
		log.Fatal(err)
	}

	defer rep.Body.Close()
	fmt.Printf("%q\n", b)
}
