package certkit

import (
	"testing"

	"github.com/go-sdk/core/errx"
)

func TestFormatRoundTrips(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmEC)
	store := NewStore()
	if err := store.AddKeyPair("server", pki.leaf.PrivateKey.Signer, certificateOf(pki.leaf), certificateOf(pki.intermediate), certificateOf(pki.root)); err != nil {
		t.Fatal(err)
	}
	t.Run("pem", func(t *testing.T) {
		data, report, err := store.Encode(FormatPEM, EncodeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		opened, err := Open(data, OpenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(opened.Certificates) != 3 || len(opened.PrivateKeys) != 1 || report.CertificatesWritten != 3 || report.PrivateKeysWritten != 1 {
			t.Fatalf("unexpected PEM round trip: certs=%d keys=%d report=%+v", len(opened.Certificates), len(opened.PrivateKeys), report)
		}
	})
	t.Run("encrypted-pem", func(t *testing.T) {
		password := []byte("pem-password")
		data, _, err := store.Encode(FormatPEM, EncodeOptions{Password: password, EncryptPEMPrivateKey: true})
		if err != nil {
			t.Fatal(err)
		}
		opened, err := Open(data, OpenOptions{Password: password})
		if err != nil {
			t.Fatal(err)
		}
		if len(opened.Certificates) != 3 || len(opened.PrivateKeys) != 1 {
			t.Fatalf("unexpected encrypted PEM round trip: certs=%d keys=%d", len(opened.Certificates), len(opened.PrivateKeys))
		}
		partial, err := Open(data, OpenOptions{Password: []byte("wrong-password")})
		if !errx.Is(err, ErrPassword) || partial == nil {
			t.Fatalf("expected partial store and ErrPassword, got store=%v error=%v", partial != nil, err)
		}
		if len(partial.Certificates) != 3 || len(partial.PrivateKeys) != 0 {
			t.Fatalf("unexpected encrypted PEM password result: certs=%d keys=%d error=%v", len(partial.Certificates), len(partial.PrivateKeys), err)
		}
	})
	t.Run("pkcs7", func(t *testing.T) {
		data, report, err := store.Encode(FormatPKCS7, EncodeOptions{AllowLossy: true})
		if err != nil {
			t.Fatal(err)
		}
		opened, err := Open(data, OpenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(opened.Certificates) != 3 || len(opened.PrivateKeys) != 0 || report.DiscardedPrivateKeys != 1 {
			t.Fatalf("unexpected PKCS7 round trip: certs=%d keys=%d report=%+v", len(opened.Certificates), len(opened.PrivateKeys), report)
		}
	})
	t.Run("pkcs12", func(t *testing.T) {
		password := []byte("p12-password")
		data, report, err := store.Encode(FormatPKCS12, EncodeOptions{Password: password, Alias: "server"})
		if err != nil {
			t.Fatal(err)
		}
		opened, err := Open(data, OpenOptions{Password: password})
		if err != nil {
			t.Fatal(err)
		}
		if len(opened.Certificates) != 3 || len(opened.PrivateKeys) != 1 || report.PrivateKeysWritten != 1 {
			t.Fatalf("unexpected PKCS12 round trip: certs=%d keys=%d report=%+v", len(opened.Certificates), len(opened.PrivateKeys), report)
		}
	})
	t.Run("jks", func(t *testing.T) {
		storePassword := []byte("store-password")
		keyPassword := []byte("entry-password")
		data, report, err := store.Encode(FormatJKS, EncodeOptions{Password: storePassword, KeyPasswords: map[string][]byte{"SERVER": keyPassword}})
		if err != nil {
			t.Fatal(err)
		}
		opened, err := Open(data, OpenOptions{Password: storePassword, KeyPasswords: map[string][]byte{"SERVER": keyPassword}})
		if err != nil {
			t.Fatal(err)
		}
		if len(opened.Certificates) != 3 || len(opened.PrivateKeys) != 1 || len(opened.Entries) != 1 || opened.Entries[0].Alias != "server" || report.PrivateKeysWritten != 1 {
			t.Fatalf("unexpected JKS round trip: certs=%d keys=%d entries=%d report=%+v", len(opened.Certificates), len(opened.PrivateKeys), len(opened.Entries), report)
		}
		partial, err := Open(data, OpenOptions{Password: storePassword, KeyPasswords: map[string][]byte{"server": []byte("wrong-password")}, DisableJKSDefaultPassword: true})
		if !errx.Is(err, ErrPassword) {
			t.Fatalf("expected ErrPassword, got %v", err)
		}
		if partial == nil || len(partial.Certificates) != 3 || len(partial.PrivateKeys) != 0 || partial.Entries[0].PrivateKeyStatus != PrivateKeyStatusUnavailable {
			t.Fatalf("unexpected partial JKS result: %+v", partial)
		}
	})
}

func TestJKSDefaultPasswordAndAlias(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmRSA)
	store := NewStore()
	if err := store.AddPrivateKey(pki.leaf.PrivateKey.Signer); err != nil {
		t.Fatal(err)
	}
	if err := store.AddCertificate(certificateOf(pki.leaf)); err != nil {
		t.Fatal(err)
	}
	data, _, err := store.Encode(FormatJKS, EncodeOptions{Password: []byte("changeit")})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(data, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.Entries) != 1 || opened.Entries[0].Alias != "mykey" || opened.Entries[0].PrivateKeyStatus != PrivateKeyStatusAvailable {
		t.Fatalf("JDK defaults were not preserved: %+v", opened.Entries)
	}
}

func TestPasswordsLossyAndUnsupportedFormats(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmRSA, KeyAlgorithmRSA)
	store := NewStore()
	if err := store.AddKeyPair("server", pki.leaf.PrivateKey.Signer, certificateOf(pki.leaf), certificateOf(pki.intermediate), certificateOf(pki.root)); err != nil {
		t.Fatal(err)
	}
	for _, format := range []Format{FormatPKCS12, FormatJKS} {
		if _, _, err := store.Encode(format, EncodeOptions{}); !errx.Is(err, ErrPassword) {
			t.Fatalf("%s output without password returned %v", format, err)
		}
	}
	if _, _, err := store.Encode(FormatPKCS7, EncodeOptions{}); !errx.Is(err, ErrLossyConversion) {
		t.Fatalf("PKCS7 lossy conversion returned %v", err)
	}
	for _, format := range []Format{FormatJCEKS, FormatBKS} {
		if _, _, err := store.Encode(format, EncodeOptions{Password: []byte("password")}); !errx.Is(err, ErrUnsupportedFormat) {
			t.Fatalf("%s output returned %v", format, err)
		}
		if _, err := Open([]byte{1}, OpenOptions{Format: format}); !errx.Is(err, ErrUnsupportedFormat) {
			t.Fatalf("%s input returned %v", format, err)
		}
	}
}

func TestShangMiPKCS12RoundTrip(t *testing.T) {
	pki := newTestPKI(t, KeyAlgorithmSM2, KeyAlgorithmSM2)
	store := NewStore()
	if err := store.AddKeyPair("sm2", pki.leaf.PrivateKey.Signer, certificateOf(pki.leaf), certificateOf(pki.intermediate), certificateOf(pki.root)); err != nil {
		t.Fatal(err)
	}
	password := []byte("sm2-password")
	data, _, err := store.Encode(FormatPKCS12, EncodeOptions{Password: password, Alias: "sm2", PKCS12Profile: PKCS12ProfileShangMi})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(data, OpenOptions{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.PrivateKeys) != 1 || opened.PrivateKeys[0].Algorithm != KeyAlgorithmSM2 || len(opened.Certificates) != 3 {
		t.Fatalf("unexpected ShangMi PKCS12 round trip: certs=%d keys=%+v", len(opened.Certificates), opened.PrivateKeys)
	}
}
