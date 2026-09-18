package certkit

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/smx509"
)

type publicCertificateExpectation struct {
	name            string
	url             string
	format          Format
	algorithm       KeyAlgorithm
	minimumCerts    int
	subjectContains string
}

func TestNetworkPublicX509Certificates(t *testing.T) {
	requireNetworkTests(t)
	cases := []publicCertificateExpectation{
		{
			name:            "apple-ecc-root-pem",
			url:             "https://www.apple.com/certificateauthority/apki202505/AppleIssuingAuthorityECCRootCAG1.pem",
			format:          FormatPEM,
			algorithm:       KeyAlgorithmEC,
			minimumCerts:    1,
			subjectContains: "Apple Issuing Authority ECC Root CA - G1",
		},
		{
			name:            "apple-ecc-chain-pem",
			url:             "https://www.apple.com/certificateauthority/apki202505/AppleIssuingAuthorityECCCA1G1.pem",
			format:          FormatPEM,
			algorithm:       KeyAlgorithmEC,
			minimumCerts:    2,
			subjectContains: "Apple Issuing Authority ECC CA 1 - G1",
		},
		{
			name:            "digicert-grid-ca-pem",
			url:             "https://cacerts.digicert.com/DigiCertGridCA-1.crt.pem",
			format:          FormatPEM,
			algorithm:       KeyAlgorithmRSA,
			minimumCerts:    1,
			subjectContains: "DigiCert Grid CA-1",
		},
		{
			name:            "digicert-grid-ca-der",
			url:             "https://cacerts.digicert.com/DigiCertGridCA-1.crt",
			format:          FormatDER,
			algorithm:       KeyAlgorithmRSA,
			minimumCerts:    1,
			subjectContains: "DigiCert Grid CA-1",
		},
		{
			name:            "microsoft-public-rsa-timestamping-ca-der",
			url:             "https://www.microsoft.com/pkiops/certs/Microsoft%20Public%20RSA%20Timestamping%20CA%202020.crt",
			format:          FormatDER,
			algorithm:       KeyAlgorithmRSA,
			minimumCerts:    1,
			subjectContains: "Microsoft Public RSA Timestamping CA 2020",
		},
		{
			name:            "microsoft-ecc-product-root-der",
			url:             "https://www.microsoft.com/pkiops/certs/Microsoft%20ECC%20Product%20Root%20Certificate%20Authority%202018.crt",
			format:          FormatDER,
			algorithm:       KeyAlgorithmEC,
			minimumCerts:    1,
			subjectContains: "Microsoft ECC Product Root Certificate Authority 2018",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			data := fetchNetworkFixture(t, testCase.url, 2<<20)
			store, err := Open(data, OpenOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if store.Source.Format != testCase.format {
				t.Fatalf("unexpected format: got %s want %s", store.Source.Format, testCase.format)
			}
			if len(store.Certificates) < testCase.minimumCerts || len(store.PrivateKeys) != 0 {
				t.Fatalf("unexpected public certificate result: certs=%d keys=%d", len(store.Certificates), len(store.PrivateKeys))
			}
			certificate := store.Certificates[0].Certificate
			if !certificate.IsCA || publicKeyAlgorithm(certificate.PublicKey) != testCase.algorithm {
				t.Fatalf("unexpected CA certificate: subject=%q algorithm=%s isCA=%v", certificate.Subject.CommonName, publicKeyAlgorithm(certificate.PublicKey), certificate.IsCA)
			}
			if !strings.Contains(certificate.Subject.CommonName, testCase.subjectContains) {
				t.Fatalf("unexpected certificate subject %q", certificate.Subject.CommonName)
			}
			if testCase.minimumCerts > 1 && !storeContainsSignedIssuerPair(store) {
				t.Fatal("public certificate bundle does not contain a valid issuer relationship")
			}
			checkPublicCertificateTrustStores(t, store)
		})
	}
}

func TestNetworkPublicNuGetPKCS7(t *testing.T) {
	requireNetworkTests(t)
	data := fetchNetworkFixture(t, "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", 8<<20)
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var signature []byte
	for _, file := range reader.File {
		if !strings.EqualFold(file.Name, ".signature.p7s") {
			continue
		}
		stream, openErr := file.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		signature, err = io.ReadAll(io.LimitReader(stream, 2<<20))
		_ = stream.Close()
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if len(signature) == 0 {
		t.Fatal("NuGet package does not contain .signature.p7s")
	}
	store, err := Open(signature, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if store.Source.Format != FormatPKCS7 || len(store.Certificates) == 0 || len(store.PrivateKeys) != 0 {
		t.Fatalf("unexpected NuGet signature result: format=%s certs=%d keys=%d", store.Source.Format, len(store.Certificates), len(store.PrivateKeys))
	}
	if !storeHasExtendedKeyUsage(store, smx509.ExtKeyUsageCodeSigning) {
		t.Fatal("NuGet signature does not contain a code-signing certificate")
	}
}

func TestNetworkPublicSigstoreCertificate(t *testing.T) {
	requireNetworkTests(t)
	data := fetchNetworkFixture(t, "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64.sigstore.json", 2<<20)
	var bundle struct {
		VerificationMaterial struct {
			Certificate struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificate"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(bundle.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(der, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if store.Source.Format != FormatDER || len(store.Certificates) != 1 || len(store.PrivateKeys) != 0 {
		t.Fatalf("unexpected Sigstore certificate result: format=%s certs=%d keys=%d", store.Source.Format, len(store.Certificates), len(store.PrivateKeys))
	}
	certificate := store.Certificates[0].Certificate
	if certificate.IsCA || !hasExtendedKeyUsage(certificate, smx509.ExtKeyUsageCodeSigning) {
		t.Fatalf("unexpected Sigstore code-signing certificate: subject=%q isCA=%v", certificate.Subject.String(), certificate.IsCA)
	}
}

func storeHasExtendedKeyUsage(store *Store, usage smx509.ExtKeyUsage) bool {
	for _, certificate := range store.Certificates {
		if hasExtendedKeyUsage(certificate.Certificate, usage) {
			return true
		}
	}
	return false
}

func hasExtendedKeyUsage(certificate *smx509.Certificate, usage smx509.ExtKeyUsage) bool {
	for _, value := range certificate.ExtKeyUsage {
		if value == usage {
			return true
		}
	}
	return false
}

func storeContainsSignedIssuerPair(store *Store) bool {
	for _, child := range store.Certificates {
		for _, issuer := range store.Certificates {
			if child.ID != issuer.ID && child.Certificate.CheckSignatureFrom(issuer.Certificate) == nil {
				return true
			}
		}
	}
	return false
}

func checkPublicCertificateTrustStores(t *testing.T, store *Store) {
	t.Helper()
	password := []byte("public-certificate-test")
	for _, format := range []Format{FormatPKCS12, FormatJKS} {
		encoded, _, err := store.Encode(format, EncodeOptions{Password: password})
		if err != nil {
			t.Fatalf("encode public certificates as %s: %v", format, err)
		}
		reopened, err := Open(encoded, OpenOptions{Password: password, DisableJKSDefaultPassword: true})
		if err != nil {
			t.Fatalf("reopen public certificates as %s: %v", format, err)
		}
		if len(reopened.Certificates) != len(store.Certificates) || len(reopened.PrivateKeys) != 0 {
			t.Fatalf("unexpected %s truststore result: certs=%d keys=%d", format, len(reopened.Certificates), len(reopened.PrivateKeys))
		}
	}
}
