package certkit

import (
	"bytes"
	"strings"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func (s *Store) encodeJKS(options EncodeOptions, report *ConversionReport) ([]byte, error) {
	if len(options.Password) < 6 {
		return nil, errx.Wrap(ErrPassword, "jks store password must contain at least six bytes")
	}
	keyStore := keystore.New(keystore.WithCaseExactAliases(), keystore.WithOrderedAliases(), keystore.WithMinPasswordLen(6))
	usedAliases := map[string]struct{}{}
	writtenCertificates := map[string]struct{}{}
	for _, entry := range s.Entries {
		alias := strings.TrimSpace(entry.Alias)
		if entry.PrivateKey != nil && isSyntheticKeyAlias(entry) {
			alias = strings.TrimSpace(options.Aliases[entry.PrivateKey.ID])
			if alias == "" && len(s.PrivateKeys) == 1 {
				alias = strings.TrimSpace(options.Alias)
				if alias == "" {
					alias = "mykey"
				}
			}
		}
		if alias == "" {
			return nil, errx.Wrap(ErrInvalidData, "jks entry alias must not be empty")
		}
		key := strings.ToLower(alias)
		if _, exists := usedAliases[key]; exists {
			return nil, errx.Wrapf(ErrAliasConflict, "alias %q", alias)
		}
		usedAliases[key] = struct{}{}
		if entry.PrivateKey != nil {
			keyPassword, _ := passwordByAlias(options.KeyPasswords, entry.Alias)
			if len(keyPassword) == 0 {
				keyPassword, _ = passwordByAlias(options.KeyPasswords, alias)
			}
			if len(keyPassword) == 0 {
				keyPassword = options.KeyPassword
			}
			if len(keyPassword) == 0 {
				keyPassword = options.Password
			}
			if len(keyPassword) < 6 {
				return nil, errx.Wrapf(ErrPassword, "jks key password for alias %q must contain at least six bytes", alias)
			}
			if len(entry.Chain) == 0 {
				return nil, errx.Wrapf(ErrNoCertificate, "jks private key entry %q has no certificate", alias)
			}
			if !publicKeysEqual(entry.PrivateKey.Signer.Public(), entry.Chain[0].Certificate.PublicKey) {
				return nil, errx.Wrapf(ErrKeyMismatch, "alias %q", alias)
			}
			der, err := smx509.MarshalPKCS8PrivateKey(entry.PrivateKey.Signer)
			if err != nil {
				return nil, errx.Wrap(err, "marshal jks private key")
			}
			chain := make([]keystore.Certificate, 0, len(entry.Chain))
			for _, cert := range entry.Chain {
				chain = append(chain, keystore.Certificate{Type: "X.509", Content: cert.Certificate.Raw})
				writtenCertificates[cert.ID] = struct{}{}
			}
			createdAt := entry.CreatedAt
			if createdAt.IsZero() {
				createdAt = time.Now()
			}
			if err := keyStore.SetPrivateKeyEntry(alias, keystore.PrivateKeyEntry{CreationTime: createdAt, PrivateKey: der, CertificateChain: chain}, keyPassword); err != nil {
				return nil, errx.Wrap(err, "write jks private key entry")
			}
			report.PrivateKeysWritten++
			report.CertificatesWritten += len(entry.Chain)
		} else if len(entry.Chain) > 0 {
			createdAt := entry.CreatedAt
			if createdAt.IsZero() {
				createdAt = time.Now()
			}
			if err := keyStore.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{CreationTime: createdAt, Certificate: keystore.Certificate{Type: "X.509", Content: entry.Chain[0].Certificate.Raw}}); err != nil {
				return nil, errx.Wrap(err, "write jks trusted certificate entry")
			}
			report.CertificatesWritten++
			writtenCertificates[entry.Chain[0].ID] = struct{}{}
		}
		report.Aliases = append(report.Aliases, alias)
	}
	for _, cert := range s.Certificates {
		if _, exists := writtenCertificates[cert.ID]; exists {
			continue
		}
		alias := strings.TrimSpace(cert.Source.Alias)
		if alias == "" {
			alias = defaultAlias(cert.Certificate)
		}
		if _, exists := usedAliases[strings.ToLower(alias)]; exists {
			alias = "certificate-" + cert.ID[:12]
		}
		if _, exists := usedAliases[strings.ToLower(alias)]; exists {
			return nil, errx.Wrapf(ErrAliasConflict, "alias %q", alias)
		}
		usedAliases[strings.ToLower(alias)] = struct{}{}
		if err := keyStore.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{CreationTime: time.Now(), Certificate: keystore.Certificate{Type: "X.509", Content: cert.Certificate.Raw}}); err != nil {
			return nil, errx.Wrap(err, "write jks trusted certificate entry")
		}
		report.Aliases = append(report.Aliases, alias)
		report.CertificatesWritten++
	}
	if len(keyStore.Aliases()) == 0 {
		return nil, errx.Wrap(ErrInvalidData, "store has no encodable jks entries")
	}
	var output bytes.Buffer
	if err := keyStore.Store(&output, options.Password); err != nil {
		return nil, errx.Wrap(err, "encode jks")
	}
	return output.Bytes(), nil
}
