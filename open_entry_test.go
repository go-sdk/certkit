package certkit

import (
	"testing"

	"github.com/go-sdk/core/errx"
)

func TestOpenEntry(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmEC)
	certificateData, err := pki.leaf.CertificateChainPEM(EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	privateKeyData, err := pki.leaf.PrivateKeyPEM(EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}

	entry, err := OpenEntry(certificateData, privateKeyData, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if entry.PrivateKey == nil || entry.PrivateKey.ID != pki.leaf.PrivateKey.ID {
		t.Fatal("unexpected private key")
	}
	if len(entry.Chain) != 3 {
		t.Fatalf("unexpected certificate chain length: %d", len(entry.Chain))
	}
	if entry.Chain[0].ID != pki.leaf.Chain[0].ID || entry.Chain[1].ID != pki.leaf.Chain[1].ID || entry.Chain[2].ID != pki.leaf.Chain[2].ID {
		t.Fatal("certificate chain is not ordered from leaf to root")
	}
}

func TestOpenEntryRejectsMismatchedPrivateKey(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmEC)
	otherPKI := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmEC)
	certificateData, err := pki.leaf.CertificateChainPEM(EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	privateKeyData, err := otherPKI.leaf.PrivateKeyPEM(EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenEntry(certificateData, privateKeyData, OpenOptions{}); !errx.Is(err, ErrKeyMismatch) {
		t.Fatalf("expected ErrKeyMismatch, got %v", err)
	}
}
