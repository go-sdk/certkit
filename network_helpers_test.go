package certkit

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

const defaultNetworkFixtureMaxSize = 16 << 20

func requireNetworkTests(t *testing.T) {
	t.Helper()
	if os.Getenv("CERTKIT_NETWORK_TESTS") != "1" {
		t.Skip("set CERTKIT_NETWORK_TESTS=1 to run public certificate interoperability tests")
	}
}

func fetchNetworkFixture(t *testing.T, rawURL string, maxSize int64) []byte {
	t.Helper()
	if maxSize <= 0 {
		maxSize = defaultNetworkFixtureMaxSize
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("download %s: unexpected HTTP status %d", rawURL, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) > maxSize {
		t.Fatalf("download %s: response exceeds %d bytes", rawURL, maxSize)
	}
	return data
}
