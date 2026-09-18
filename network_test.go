package certkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"
	"time"
)

type networkDemoExpectation struct {
	name              string
	host              string
	algorithm         KeyAlgorithm
	algorithmFromRoot bool
	state             string
}

func TestNetworkPublicCADemoSites(t *testing.T) {
	requireNetworkTests(t)
	cases := []networkDemoExpectation{
		{
			name:      "digicert-rsa-valid",
			host:      "global-root-g2.chain-demos.digicert.com",
			algorithm: KeyAlgorithmRSA,
			state:     "valid",
		},
		{
			name:              "digicert-ecdsa-valid",
			host:              "global-root-g3.chain-demos.digicert.com",
			algorithm:         KeyAlgorithmEC,
			algorithmFromRoot: true,
			state:             "valid",
		},
		{
			name:  "digicert-expired",
			host:  "global-root-g2-expired.chain-demos.digicert.com",
			state: "expired",
		},
		{
			name:  "digicert-revoked",
			host:  "global-root-g2-revoked.chain-demos.digicert.com",
			state: "revoked",
		},
		{
			name:      "letsencrypt-rsa-valid",
			host:      "valid.x1.test-certs.letsencrypt.org",
			algorithm: KeyAlgorithmRSA,
			state:     "valid",
		},
		{
			name:      "letsencrypt-ecdsa-valid",
			host:      "valid.x2.test-certs.letsencrypt.org",
			algorithm: KeyAlgorithmEC,
			state:     "valid",
		},
		{
			name:  "letsencrypt-expired",
			host:  "expired.x1.test-certs.letsencrypt.org",
			state: "expired",
		},
		{
			name:  "letsencrypt-revoked",
			host:  "revoked.x1.test-certs.letsencrypt.org",
			state: "revoked",
		},
		{
			name:      "amazon-rsa-valid",
			host:      "valid.rootca1.demo.amazontrust.com",
			algorithm: KeyAlgorithmRSA,
			state:     "valid",
		},
		{
			name:      "amazon-ecdsa-valid",
			host:      "valid.rootca3.demo.amazontrust.com",
			algorithm: KeyAlgorithmEC,
			state:     "valid",
		},
		{
			name:  "amazon-expired",
			host:  "expired.rootca1.demo.amazontrust.com",
			state: "expired",
		},
		{
			name:  "amazon-revoked",
			host:  "revoked.rootca1.demo.amazontrust.com",
			state: "revoked",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			checkNetworkDemoSite(t, testCase)
		})
	}
}

func checkNetworkDemoSite(t *testing.T, expectation networkDemoExpectation) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	roots, err := MozillaRoots()
	if err != nil {
		t.Fatal(err)
	}
	report, err := InspectTLS(ctx, expectation.host, TLSOptions{ServerName: expectation.host, Versions: []TLSVersion{TLS12}, Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	result := report.Versions[0]
	if !result.HandshakeSucceeded {
		t.Fatalf("TLS handshake failed at %s: %+v", expectation.host, result.Failure)
	}
	if result.PeerCertificates == nil || len(result.PeerCertificates.Certificates) < 2 {
		t.Fatalf("%s did not serve a leaf and issuer certificate", expectation.host)
	}
	leaf := result.PeerCertificates.Certificates[0].Certificate
	issuer := result.PeerCertificates.Certificates[1].Certificate
	algorithmCertificate := leaf
	if expectation.algorithmFromRoot {
		algorithmCertificate = result.PeerCertificates.Certificates[len(result.PeerCertificates.Certificates)-1].Certificate
	}
	if expectation.algorithm != "" && publicKeyAlgorithm(algorithmCertificate.PublicKey) != expectation.algorithm {
		t.Fatalf("%s served %s instead of %s", expectation.host, publicKeyAlgorithm(algorithmCertificate.PublicKey), expectation.algorithm)
	}
	switch expectation.state {
	case "valid":
		if !result.Validation.Trusted || !result.Validation.HostnameValid || !result.Validation.ServedChainComplete {
			t.Fatalf("valid demo site failed validation: %+v", result.Validation)
		}
	case "expired":
		if time.Now().Before(leaf.NotAfter) || result.Validation.Trusted {
			t.Fatalf("expired demo site was not reported expired: notAfter=%s validation=%+v", leaf.NotAfter, result.Validation)
		}
	case "revoked":
		crlResult, crlErr := FetchAndCheckCRL(ctx, nil, leaf, issuer, CRLOptions{})
		if crlErr != nil {
			t.Fatal(crlErr)
		}
		if !crlResult.Revoked || !crlResult.SignatureValid || !crlResult.Fresh {
			t.Fatalf("revoked demo site did not produce a valid revoked CRL result: %+v", crlResult)
		}
	default:
		t.Fatalf("unknown demo state %q", expectation.state)
	}
}

func publicKeyAlgorithm(publicKey any) KeyAlgorithm {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return KeyAlgorithmRSA
	case *ecdsa.PublicKey:
		return KeyAlgorithmEC
	default:
		return KeyAlgorithmUnknown
	}
}
