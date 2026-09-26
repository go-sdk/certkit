package certkit

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
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

func TestInspectTLCPUsesSNIAndCollectsDualCertificates(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmSM2, KeyAlgorithmSM2)
	encryptionOptions := CertificateOptions{
		Alias:       "server-encryption",
		Subject:     pkix.Name{CommonName: "service.test"},
		DNSNames:    []string{"service.test"},
		NotBefore:   testCurrentTime.Add(-time.Hour),
		NotAfter:    testCurrentTime.Add(24 * time.Hour),
		Key:         KeyOptions{Algorithm: KeyAlgorithmSM2},
		KeyUsage:    smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment,
		ExtKeyUsage: []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
	}
	encryption, err := IssueCertificate(pki.intermediate, encryptionOptions)
	if err != nil {
		t.Fatal(err)
	}
	address, serverNames := startLocalTLCPServer(t, pki.leaf, encryption, certificateOf(pki.intermediate))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	options := TLSOptions{
		ServerName:  "service.test",
		Versions:    []TLSVersion{TLCP11},
		Roots:       CustomRoots(certificateOf(pki.root)),
		CurrentTime: testCurrentTime,
	}
	report, err := InspectTLS(ctx, address, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Versions) != 1 {
		t.Fatalf("unexpected TLCP result count: %d", len(report.Versions))
	}
	result := report.Versions[0]
	if !result.HandshakeSucceeded || result.NegotiatedVersion != uint16(TLCP11) || !result.Validation.HostnameValid || !result.Validation.Trusted || !result.Validation.ServedChainComplete || result.Validation.ContainsRoot {
		t.Fatalf("unexpected TLCP result: %+v", result)
	}
	if result.PeerCertificates == nil || len(result.PeerCertificates.Certificates) != 3 {
		t.Fatalf("unexpected TLCP certificate count: %+v", result.PeerCertificates)
	}
	select {
	case serverName := <-serverNames:
		if serverName != "service.test" {
			t.Fatalf("unexpected TLCP SNI: %q", serverName)
		}
	case <-ctx.Done():
		t.Fatal("TLCP server did not observe SNI")
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

func startLocalTLCPServer(t *testing.T, signing, encryption *Entry, chain ...*smx509.Certificate) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	signingDER := [][]byte{certificateOf(signing).Raw}
	encryptionDER := [][]byte{certificateOf(encryption).Raw}
	for _, cert := range chain {
		signingDER = append(signingDER, cert.Raw)
		encryptionDER = append(encryptionDER, cert.Raw)
	}
	serverNames := make(chan string, 1)
	getConfigForClient := func(hello *tlcp.ClientHelloInfo) (*tlcp.Config, error) {
		serverNames <- hello.ServerName
		return nil, nil
	}
	config := &tlcp.Config{
		Certificates: []tlcp.Certificate{
			{
				Certificate: signingDER,
				PrivateKey:  signing.PrivateKey.Signer,
				Leaf:        certificateOf(signing),
			},
			{
				Certificate: encryptionDER,
				PrivateKey:  encryption.PrivateKey.Signer,
				Leaf:        certificateOf(encryption),
			},
		},
		GetConfigForClient: getConfigForClient,
	}
	tlcpListener := tlcp.NewListener(listener, config)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, acceptErr := tlcpListener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = connection.Close() }()
				if tlcpConnection, ok := connection.(*tlcp.Conn); ok {
					_ = tlcpConnection.Handshake()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = tlcpListener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})
	return listener.Addr().String(), serverNames
}
