package certkit

import (
	"bytes"
	"crypto"
	"strings"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func openJKS(data []byte, options OpenOptions) (*Store, error) {
	passwords, err := jksStorePasswords(options)
	if err != nil {
		passwords = [][]byte{nil}
	}
	var selected []byte
	var keyStore keystore.KeyStore
	var loadErr error
	for _, password := range passwords {
		candidate := keystore.New(keystore.WithCaseExactAliases(), keystore.WithOrderedAliases())
		loadErr = candidate.Load(bytes.NewReader(data), password)
		keyStore = candidate
		if loadErr == nil {
			selected = password
			break
		}
	}
	store := NewStore()
	store.Source = SourceInfo{Format: FormatJKS, Encoding: EncodingDER, IntegrityVerified: loadErr == nil}
	if loadErr != nil && !strings.Contains(loadErr.Error(), "invalid digest") {
		return nil, errx.Wrap(ErrInvalidData, "parse jks")
	}
	aliases := keyStore.Aliases()
	for _, alias := range aliases {
		if keyStore.IsTrustedCertificateEntry(alias) {
			entry, entryErr := keyStore.GetTrustedCertificateEntry(alias)
			if entryErr != nil {
				return nil, errx.Wrap(entryErr, "read jks trusted certificate entry")
			}
			cert, certErr := parseJKSCertificate(entry.Certificate)
			if certErr != nil {
				return nil, certErr
			}
			item, _ := NewCertificate(cert)
			item.Source = SourceRef{Format: FormatJKS, Alias: alias}
			store.addCertificate(item)
			store.Entries = append(store.Entries, &Entry{
				Alias:     alias,
				CreatedAt: entry.CreationTime,
				Chain:     []*Certificate{store.certificateByID(item.ID)},
				Trusted:   true,
			})
			continue
		}
		if !keyStore.IsPrivateKeyEntry(alias) {
			continue
		}
		chain, chainErr := keyStore.GetPrivateKeyEntryCertificateChain(alias)
		if chainErr != nil {
			return nil, errx.Wrap(chainErr, "read jks certificate chain")
		}
		certificates := make([]*Certificate, 0, len(chain))
		for i, rawCert := range chain {
			cert, certErr := parseJKSCertificate(rawCert)
			if certErr != nil {
				return nil, certErr
			}
			item, _ := NewCertificate(cert)
			item.Source = SourceRef{Format: FormatJKS, Alias: alias, Index: i}
			store.addCertificate(item)
			certificates = append(certificates, store.certificateByID(item.ID))
		}
		entry := &Entry{Alias: alias, Chain: certificates, PrivateKeyStatus: PrivateKeyStatusUnavailable}
		if loadErr == nil {
			privateKey, keyErr := decryptJKSPrivateKey(keyStore, alias, selected, options)
			if keyErr == nil {
				item, itemErr := NewPrivateKey(privateKey)
				if itemErr != nil {
					return nil, itemErr
				}
				item.Source = SourceRef{Format: FormatJKS, Alias: alias}
				store.addPrivateKey(item)
				entry.PrivateKey = store.privateKeyByID(item.ID)
				entry.PrivateKeyStatus = PrivateKeyStatusAvailable
			} else {
				store.Diagnostics = append(store.Diagnostics, Diagnostic{
					Level:   DiagnosticWarning,
					Code:    "private_key_password",
					Message: "jks private key password is required or incorrect",
					Alias:   alias,
				})
				loadErr = errx.Join(loadErr, keyErr)
			}
		}
		store.Entries = append(store.Entries, entry)
	}
	if loadErr != nil {
		store.Diagnostics = append(store.Diagnostics, Diagnostic{Level: DiagnosticWarning, Code: "integrity_unverified", Message: "jks integrity or private keys could not be verified"})
		return store, errx.Wrap(ErrPassword, "open jks")
	}
	return store, nil
}

func parseJKSCertificate(raw keystore.Certificate) (*smx509.Certificate, error) {
	if !strings.EqualFold(raw.Type, "X509") && !strings.EqualFold(raw.Type, "X.509") {
		return nil, errx.Wrapf(ErrUnsupportedFormat, "jks certificate type %q", raw.Type)
	}
	cert, err := smx509.ParseCertificate(raw.Content)
	if err != nil {
		return nil, errx.Wrap(err, "parse jks certificate")
	}
	return cert, nil
}

func decryptJKSPrivateKey(keyStore keystore.KeyStore, alias string, storePassword []byte, options OpenOptions) (crypto.Signer, error) {
	candidates := make([][]byte, 0, 4)
	if password, ok := passwordByAlias(options.KeyPasswords, alias); ok {
		candidates = append(candidates, password)
	}
	if options.PasswordProvider != nil {
		password, err := options.PasswordProvider(PasswordRequest{Format: FormatJKS, Alias: alias, Purpose: PasswordPurposePrivateKey})
		if err == nil && password != nil {
			candidates = append(candidates, password)
		}
	}
	candidates = appendUniquePassword(candidates, storePassword)
	if !options.DisableJKSDefaultPassword {
		candidates = appendUniquePassword(candidates, []byte("changeit"))
	}
	for _, password := range candidates {
		entry, err := keyStore.GetPrivateKeyEntry(alias, password)
		if err != nil {
			continue
		}
		key, parseErr := parsePrivateKey(entry.PrivateKey, nil)
		if parseErr == nil {
			return key, nil
		}
	}
	return nil, ErrPassword
}

func jksStorePasswords(options OpenOptions) ([][]byte, error) {
	if options.Password != nil {
		return [][]byte{options.Password}, nil
	}
	if options.PasswordProvider != nil {
		password, err := options.PasswordProvider(PasswordRequest{Format: FormatJKS, Purpose: PasswordPurposeContainer})
		if err != nil {
			return nil, errx.Wrap(err, "get jks password")
		}
		if password != nil {
			return [][]byte{password}, nil
		}
	}
	if !options.DisableJKSDefaultPassword {
		return [][]byte{[]byte("changeit")}, nil
	}
	return nil, ErrPassword
}
