package httphijack

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
)

// Client may be used to make hijackable http requests
type Client struct {
	TLSConfig *tls.Config
}

// Response wraps an http.Response and provides access to the underlying
// connection.
type Response struct {
	*http.Response
	conn net.Conn
}

// Hijack returns the net.Conn used by this response.
func (r *Response) Hijack() net.Conn {
	return r.conn
}

type transport struct {
	*http.Transport
	conn net.Conn
}

func (t *transport) dialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = net.Dial(network, address)
	if err != nil {
		return
	}
	t.conn = conn
	return
}

func (t *transport) dialTLS(network, address string) (conn net.Conn, err error) {
	conn, err = tls.Dial(network, address, t.TLSClientConfig)
	if err != nil {
		return
	}
	t.conn = conn
	return
}

// Do sends an HTTP request and returns an HTTP response that can be Hijacked.
func (c *Client) Do(request *http.Request) (*Response, error) {
	t := newTransport(c)
	t.TLSClientConfig = c.TLSConfig
	response, err := t.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	return &Response{
		Response: response,
		conn:     t.conn,
	}, nil
}

// NewClient creates a new Client
func NewClient() *Client {
	return &Client{}
}

func newTransport(c *Client) *transport {
	t := &transport{}
	t.Transport = &http.Transport{
		TLSClientConfig: c.TLSConfig,
		DialContext:     t.dialContext,
		DialTLS:         t.dialTLS,
	}
	return t
}
