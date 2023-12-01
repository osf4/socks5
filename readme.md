# SOCKS5

Provides the socks5 protocol that allows you to send your traffic through the proxy server. It provides the client and server versions of the protocol.

# Install

`go get github.com/osf4/socks5`

# Feature

* All commands supported (CONNECT, BIND, UDP ASSOCIATE)
* Can be used to create both client and server applications.
* No Auth and Password Authentication supported

# TODO 

* Add rules that allow users to validate requests sent by the client

# Example

```go
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
```
All examples you can find in [example](github.com/osf4/socks5/examples) folder