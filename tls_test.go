package certkit

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

func TestInspectTLSVersionsSNIAndCompleteChain(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmRSA)
	address, serverNames := startLocalTLSServer(t, pki.leaf, certificateOf(pki.intermediate))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	versions := []TLSVersion{TLS10, TLS11, TLS12, TLS13}
	options := TLSOptions{
		ServerName:   "service.test",
		Versions:     versions,
		Roots:        CustomRoots(certificateOf(pki.root)),
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		CurrentTime:  testCurrentTime,
	}
	report, err := InspectTLS(ctx, address, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Versions) != len(versions) {
		t.Fatalf("unexpected TLS result count: %d", len(report.Versions))
	}
	for _, result := range report.Versions {
		if !result.HandshakeSucceeded || result.NegotiatedVersion != uint16(result.Version) || !result.Validation.HostnameValid || !result.Validation.Trusted || !result.Validation.ServedChainComplete || result.Validation.ContainsRoot {
			t.Fatalf("unexpected %s result: %+v", result.Version, result)
		}
	}
	for range report.Versions {
		select {
		case serverName := <-serverNames:
			if serverName != "service.test" {
				t.Fatalf("unexpected SNI: %q", serverName)
			}
		case <-ctx.Done():
			t.Fatal("TLS server did not observe SNI")
		}
	}
}

func TestInspectTLSDetectsIncompleteChain(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmRSA)
	address, _ := startLocalTLSServer(t, pki.leaf)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	options := TLSOptions{
		ServerName:  "service.test",
		Versions:    []TLSVersion{TLS12},
		Roots:       CustomRoots(certificateOf(pki.root)),
		CurrentTime: testCurrentTime,
	}
	report, err := InspectTLS(ctx, address, options)
	if err != nil {
		t.Fatal(err)
	}
	result := report.Versions[0]
	if !result.HandshakeSucceeded || result.Validation.Trusted || result.Validation.ServedChainComplete || len(result.Validation.MissingIssuers) == 0 {
		t.Fatalf("incomplete chain was not reported: %+v", result)
	}
}

func startLocalTLSServer(t *testing.T, leaf *Entry, chain ...*smx509.Certificate) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	certificateDER := [][]byte{certificateOf(leaf).Raw}
	for _, cert := range chain {
		certificateDER = append(certificateDER, cert.Raw)
	}
	serverNames := make(chan string, 8)
	getConfigForClient := func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		serverNames <- hello.ServerName
		return nil, nil
	}
	config := &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: certificateDER, PrivateKey: leaf.PrivateKey.Signer}},
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		GetConfigForClient: getConfigForClient,
	}
	tlsListener := tls.NewListener(listener, config)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, acceptErr := tlsListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = connection.Close() }()
				if tlsConnection, ok := connection.(*tls.Conn); ok {
					_ = tlsConnection.Handshake()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = tlsListener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})
	return listener.Addr().String(), serverNames
}
