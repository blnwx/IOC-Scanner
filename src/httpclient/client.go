package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// Body sends req and returns the body only on a 2xx response.
func Body(client *http.Client, req *http.Request) (io.ReadCloser, error) {
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		response.Body.Close()
		return nil, fmt.Errorf("HTTP %s", response.Status)
	}
	return response.Body, nil
}

// Get sends a context-bound GET using the caller's client.
func Get(ctx context.Context, client *http.Client, endpoint string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return Body(client, req)
}
