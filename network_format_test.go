package certkit

import (
	"testing"

	"github.com/emmansun/gmsm/smx509"
)

type publicFormatExpectation struct {
	name         string
	url          string
	options      OpenOptions
	format       Format
	minimumCerts int
	minimumKeys  int
	usage        smx509.ExtKeyUsage
	checkUsage   bool
}

func TestNetworkPublicFormatFixtures(t *testing.T) {
	requireNetworkTests(t)
	cases := []publicFormatExpectation{
		{
			name: "badssl-client-pem",
			url:  "https://badssl.com/certs/badssl.com-client.pem",
			options: OpenOptions{
				Password: []byte("badssl.com"),
			},
			format:       FormatPEM,
			minimumCerts: 1,
			minimumKeys:  1,
			usage:        smx509.ExtKeyUsageClientAuth,
			checkUsage:   true,
		},
		{
			name: "badssl-client-pkcs12",
			url:  "https://badssl.com/certs/badssl.com-client.p12",
			options: OpenOptions{
				Password: []byte("badssl.com"),
			},
			format:       FormatPKCS12,
			minimumCerts: 1,
			minimumKeys:  1,
			usage:        smx509.ExtKeyUsageClientAuth,
			checkUsage:   true,
		},
		{
			name: "keystore-go-jks",
			url:  "https://raw.githubusercontent.com/pavlo-v-chernykh/keystore-go/v4.5.0/testdata/keystore_keypass.jks",
			options: OpenOptions{
				Password:                  []byte("password"),
				KeyPasswords:              map[string][]byte{"alias": []byte("keypassword")},
				DisableJKSDefaultPassword: true,
			},
			format:       FormatJKS,
			minimumCerts: 1,
			minimumKeys:  1,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			data := fetchNetworkFixture(t, testCase.url, 4<<20)
			store, err := Open(data, testCase.options)
			if err != nil {
				t.Fatal(err)
			}
			if store.Source.Format != testCase.format || len(store.Certificates) < testCase.minimumCerts || len(store.PrivateKeys) < testCase.minimumKeys {
				t.Fatalf("unexpected public format result: format=%s certs=%d keys=%d", store.Source.Format, len(store.Certificates), len(store.PrivateKeys))
			}
			if testCase.checkUsage && !storeAllowsExtendedKeyUsage(store, testCase.usage) {
				t.Fatalf("public %s sample does not allow expected extended key usage", testCase.format)
			}
			for _, entry := range store.Entries {
				if entry.PrivateKey != nil && len(entry.Chain) > 0 && !publicKeysEqual(entry.PrivateKey.Signer.Public(), entry.Chain[0].Certificate.PublicKey) {
					t.Fatalf("entry %q contains a mismatched private key", entry.Alias)
				}
			}
		})
	}
}

func storeAllowsExtendedKeyUsage(store *Store, usage smx509.ExtKeyUsage) bool {
	for _, entry := range store.Entries {
		if entry.PrivateKey != nil && len(entry.Chain) > 0 && certificateAllowsExtendedKeyUsage(entry.Chain[0].Certificate, usage) {
			return true
		}
	}
	return false
}

func certificateAllowsExtendedKeyUsage(certificate *smx509.Certificate, usage smx509.ExtKeyUsage) bool {
	if len(certificate.ExtKeyUsage) == 0 {
		return true
	}
	for _, value := range certificate.ExtKeyUsage {
		if value == smx509.ExtKeyUsageAny || value == usage {
			return true
		}
	}
	return false
}
