package certkit

import (
	"encoding/pem"
	"testing"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

func TestEntryPEMHelpers(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmEC)

	withoutRoot, err := pki.leaf.CertificateChainPEM(EncodeOptions{ExcludeRootCertificates: true})
	if err != nil {
		t.Fatal(err)
	}
	withoutRootCertificates := parsePEMCertificates(t, withoutRoot)
	if len(withoutRootCertificates) != 2 {
		t.Fatalf("unexpected certificate count without root: %d", len(withoutRootCertificates))
	}
	if !withoutRootCertificates[0].Equal(certificateOf(pki.leaf)) || !withoutRootCertificates[1].Equal(certificateOf(pki.intermediate)) {
		t.Fatal("certificate chain without root is not ordered from leaf to intermediate")
	}

	withRoot, err := pki.leaf.CertificateChainPEM(EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	withRootCertificates := parsePEMCertificates(t, withRoot)
	if len(withRootCertificates) != 3 {
		t.Fatalf("unexpected certificate count with root: %d", len(withRootCertificates))
	}
	if !withRootCertificates[2].Equal(certificateOf(pki.root)) {
		t.Fatal("certificate chain with root does not end with the root certificate")
	}

	password := []byte("private-key-password")
	privateKeyPEM, err := pki.leaf.PrivateKeyPEM(EncodeOptions{Password: password, EncryptPEMPrivateKey: true})
	if err != nil {
		t.Fatal(err)
	}
	privateKeyStore, err := Open(privateKeyPEM, OpenOptions{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKeyStore.PrivateKeys) != 1 || privateKeyStore.PrivateKeys[0].ID != pki.leaf.PrivateKey.ID {
		t.Fatal("private key PEM does not contain the entry private key")
	}
}

func TestEntryPEMHelpersRejectUnavailableData(t *testing.T) {
	root, err := CreateRootCA(RootCAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.CertificateChainPEM(EncodeOptions{ExcludeRootCertificates: true}); !errx.Is(err, ErrNoCertificate) {
		t.Fatalf("expected ErrNoCertificate for root-only chain without root, got %v", err)
	}

	entry := &Entry{PrivateKeyStatus: PrivateKeyStatusUnavailable}
	if _, err := entry.PrivateKeyPEM(EncodeOptions{}); !errx.Is(err, ErrNoPrivateKey) {
		t.Fatalf("expected ErrNoPrivateKey for unavailable private key, got %v", err)
	}
}

func parsePEMCertificates(t *testing.T, data []byte) []*smx509.Certificate {
	t.Helper()
	certificates := make([]*smx509.Certificate, 0)
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			t.Fatal("failed to decode PEM certificate")
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("unexpected PEM block type: %s", block.Type)
		}
		certificate, err := smx509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, certificate)
		data = rest
	}
	return certificates
}
