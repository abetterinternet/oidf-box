package httpclient

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Client is an HTTP client.
type Client struct {
	client http.Client
}

func New() Client {
	return Client{client: http.Client{Transport: &http.Transport{
		// TODO(timg): make TLS stuff configurable. For current test purposes, turning off TLS
		// trust verification suffices.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}}
}

// Get does an HTTP GET of the specified resource and validates that the response has the expected
// Content-Type header and returns the response body.
func (c *Client) Get(resource url.URL, contentType string) ([]byte, error) {
	resp, err := c.client.Get(resource.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EC: %w", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != contentType {
		return nil, fmt.Errorf("response has wrong content type: %s", resp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}
