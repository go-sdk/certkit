package certkit

import (
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

var testCurrentTime = time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)

type testPKI struct {
	root         *Entry
	intermediate *Entry
	leaf         *Entry
}

func newTestPKI(t *testing.T, rootAlgorithm, leafAlgorithm KeyAlgorithm) testPKI {
	t.Helper()
	rootOptions := RootCAOptions{
		Alias:     "root",
		Subject:   pkix.Name{CommonName: "Test Root"},
		NotBefore: testCurrentTime.Add(-10 * 365 * 24 * time.Hour),
		NotAfter:  testCurrentTime.Add(10 * 365 * 24 * time.Hour),
		Key:       KeyOptions{Algorithm: rootAlgorithm, RSABits: 2048},
	}
	root, err := CreateRootCA(rootOptions)
	if err != nil {
		t.Fatal(err)
	}
	intermediateOptions := CertificateOptions{
		Alias:     "intermediate",
		Subject:   pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: testCurrentTime.Add(-10 * 365 * 24 * time.Hour),
		NotAfter:  testCurrentTime.Add(5 * 365 * 24 * time.Hour),
		IsCA:      true,
		Key:       KeyOptions{Algorithm: KeyAlgorithmEC, Curve: "P-256"},
	}
	intermediate, err := IssueCertificate(root, intermediateOptions)
	if err != nil {
		t.Fatal(err)
	}
	leafOptions := CertificateOptions{
		Alias:       "server",
		Subject:     pkix.Name{CommonName: "service.test"},
		DNSNames:    []string{"service.test"},
		NotBefore:   testCurrentTime.Add(-time.Hour),
		NotAfter:    testCurrentTime.Add(24 * time.Hour),
		Key:         KeyOptions{Algorithm: leafAlgorithm, RSABits: 2048, Curve: "P-256"},
		ExtKeyUsage: []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
	}
	leaf, err := IssueCertificate(intermediate, leafOptions)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{root: root, intermediate: intermediate, leaf: leaf}
}

func certificateOf(entry *Entry) *smx509.Certificate {
	return entry.Chain[0].Certificate
}
