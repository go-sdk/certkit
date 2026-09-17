package certkit

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
	xocsp "golang.org/x/crypto/ocsp"
)

func TestCreateRootCAAlgorithms(t *testing.T) {
	for _, algorithm := range []KeyAlgorithm{KeyAlgorithmRSA, KeyAlgorithmEC, KeyAlgorithmSM2} {
		t.Run(string(algorithm), func(t *testing.T) {
			options := RootCAOptions{
				Alias:     string(algorithm),
				Subject:   pkix.Name{CommonName: string(algorithm) + " root"},
				NotBefore: testCurrentTime.Add(-time.Hour),
				NotAfter:  testCurrentTime.Add(24 * time.Hour),
				Key:       KeyOptions{Algorithm: algorithm, RSABits: 2048, Curve: "P-256"},
			}
			entry, err := CreateRootCA(options)
			if err != nil {
				t.Fatal(err)
			}
			if entry.PrivateKey.Algorithm != algorithm {
				t.Fatalf("unexpected key algorithm: %s", entry.PrivateKey.Algorithm)
			}
			cert := certificateOf(entry)
			if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
				t.Fatal("root certificate is not a valid self-signed CA")
			}
		})
	}
}

func TestVerifyCertificateValidExpiredAndHostname(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmEC)
	leaf := certificateOf(pki.leaf)
	intermediate := certificateOf(pki.intermediate)
	root := certificateOf(pki.root)
	validOptions := VerifyOptions{
		Roots:         CustomRoots(root),
		Intermediates: []*smx509.Certificate{intermediate},
		DNSName:       "service.test",
		CurrentTime:   testCurrentTime,
		KeyUsages:     []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
	}
	valid := VerifyCertificate(leaf, validOptions)
	if !valid.Trusted || !valid.HostnameValid || len(valid.Chains) != 1 {
		t.Fatalf("expected trusted chain, got trusted=%v hostname=%v chains=%d error=%v", valid.Trusted, valid.HostnameValid, len(valid.Chains), valid.Error)
	}
	expiredOptions := VerifyOptions{
		Roots:         CustomRoots(root),
		Intermediates: []*smx509.Certificate{intermediate},
		DNSName:       "service.test",
		CurrentTime:   leaf.NotAfter.Add(time.Second),
		KeyUsages:     []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
	}
	expired := VerifyCertificate(leaf, expiredOptions)
	if expired.Trusted || expired.Error == nil {
		t.Fatal("expired certificate was accepted")
	}
	wrongHostOptions := VerifyOptions{
		Roots:         CustomRoots(root),
		Intermediates: []*smx509.Certificate{intermediate},
		DNSName:       "other.test",
		CurrentTime:   testCurrentTime,
	}
	wrongHost := VerifyCertificate(leaf, wrongHostOptions)
	if wrongHost.Trusted || wrongHost.HostnameValid {
		t.Fatal("certificate was accepted for the wrong host")
	}
}

func TestCrossSignedIntermediateBuildsMultiplePaths(t *testing.T) {
	rootAOptions := RootCAOptions{
		Alias:     "root-a",
		Subject:   pkix.Name{CommonName: "Root A"},
		NotBefore: testCurrentTime.Add(-time.Hour),
		NotAfter:  testCurrentTime.Add(365 * 24 * time.Hour),
		Key:       KeyOptions{Algorithm: KeyAlgorithmRSA, RSABits: 2048},
	}
	rootA, err := CreateRootCA(rootAOptions)
	if err != nil {
		t.Fatal(err)
	}
	rootBOptions := RootCAOptions{
		Alias:     "root-b",
		Subject:   pkix.Name{CommonName: "Root B"},
		NotBefore: testCurrentTime.Add(-time.Hour),
		NotAfter:  testCurrentTime.Add(365 * 24 * time.Hour),
		Key:       KeyOptions{Algorithm: KeyAlgorithmEC, Curve: "P-256"},
	}
	rootB, err := CreateRootCA(rootBOptions)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := GeneratePrivateKey(KeyOptions{Algorithm: KeyAlgorithmEC, Curve: "P-256"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := CreateCertificateRequest(intermediateKey, CSROptions{Subject: pkix.Name{CommonName: "Cross Intermediate"}})
	if err != nil {
		t.Fatal(err)
	}
	certificateOptions := CertificateOptions{
		Alias:     "cross",
		IsCA:      true,
		NotBefore: testCurrentTime.Add(-time.Hour),
		NotAfter:  testCurrentTime.Add(180 * 24 * time.Hour),
	}
	crossA, err := SignCertificateRequest(rootA, csr, certificateOptions)
	if err != nil {
		t.Fatal(err)
	}
	crossB, err := SignCertificateRequest(rootB, csr, certificateOptions)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := NewPrivateKey(intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &Entry{
		Alias:            "cross",
		PrivateKey:       privateKey,
		PrivateKeyStatus: PrivateKeyStatusAvailable,
		Chain:            crossA.Chain,
	}
	leafOptions := CertificateOptions{
		Alias:     "leaf",
		Subject:   pkix.Name{CommonName: "multipath.test"},
		DNSNames:  []string{"multipath.test"},
		NotBefore: testCurrentTime.Add(-time.Hour),
		NotAfter:  testCurrentTime.Add(24 * time.Hour),
		Key:       KeyOptions{Algorithm: KeyAlgorithmRSA, RSABits: 2048},
	}
	leaf, err := IssueCertificate(issuer, leafOptions)
	if err != nil {
		t.Fatal(err)
	}
	intermediates := []*smx509.Certificate{certificateOf(crossA), certificateOf(crossB)}
	for name, root := range map[string]*smx509.Certificate{"root-a": certificateOf(rootA), "root-b": certificateOf(rootB)} {
		t.Run(name, func(t *testing.T) {
			options := VerifyOptions{
				Roots:         CustomRoots(root),
				Intermediates: intermediates,
				DNSName:       "multipath.test",
				CurrentTime:   testCurrentTime,
			}
			result := VerifyCertificate(certificateOf(leaf), options)
			if !result.Trusted || len(result.Chains) == 0 {
				t.Fatalf("cross-signed path was not built: %v", result.Error)
			}
		})
	}
}

func TestCRLAndOCSPStatus(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmRSA)
	leaf := certificateOf(pki.leaf)
	issuer := certificateOf(pki.intermediate)
	crlOptions := CreateCRLOptions{
		Number:     big.NewInt(7),
		ThisUpdate: testCurrentTime.Add(-time.Hour),
		NextUpdate: testCurrentTime.Add(time.Hour),
		Certificates: []RevokedCertificate{{
			SerialNumber:   leaf.SerialNumber,
			RevocationTime: testCurrentTime.Add(-30 * time.Minute),
			ReasonCode:     1,
		}},
	}
	crlData, err := CreateCRL(pki.intermediate, crlOptions)
	if err != nil {
		t.Fatal(err)
	}
	crlResult, err := CheckCRL(leaf, issuer, crlData, CRLOptions{CurrentTime: testCurrentTime})
	if err != nil {
		t.Fatal(err)
	}
	if !crlResult.Revoked || !crlResult.SignatureValid || !crlResult.Fresh || crlResult.ReasonCode != 1 {
		t.Fatalf("unexpected CRL result: %+v", crlResult)
	}
	standardIssuer, err := x509.ParseCertificate(issuer.Raw)
	if err != nil {
		t.Fatal(err)
	}
	standardLeaf, err := x509.ParseCertificate(leaf.Raw)
	if err != nil {
		t.Fatal(err)
	}
	ocspTemplate := xocsp.Response{
		Status:           xocsp.Revoked,
		SerialNumber:     standardLeaf.SerialNumber,
		ProducedAt:       testCurrentTime,
		ThisUpdate:       testCurrentTime.Add(-time.Hour),
		NextUpdate:       testCurrentTime.Add(time.Hour),
		RevokedAt:        testCurrentTime.Add(-30 * time.Minute),
		RevocationReason: xocsp.KeyCompromise,
	}
	ocspData, err := xocsp.CreateResponse(standardIssuer, standardIssuer, ocspTemplate, pki.intermediate.PrivateKey.Signer)
	if err != nil {
		t.Fatal(err)
	}
	ocspResult, err := CheckOCSP(leaf, issuer, ocspData, OCSPOptions{CurrentTime: testCurrentTime})
	if err != nil {
		t.Fatal(err)
	}
	if ocspResult.Status != xocsp.Revoked || !ocspResult.Fresh || ocspResult.RevocationReason != xocsp.KeyCompromise {
		t.Fatalf("unexpected OCSP result: %+v", ocspResult)
	}
}
