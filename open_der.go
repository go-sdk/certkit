package certkit

import (
	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

func openDER(data []byte, options OpenOptions) (*Store, error) {
	store := NewStore()
	store.Source = SourceInfo{Format: FormatDER, Encoding: EncodingDER, IntegrityVerified: true}
	if certs, err := smx509.ParseCertificates(data); err == nil {
		for i, cert := range certs {
			item, _ := NewCertificate(cert)
			item.Source = SourceRef{Format: FormatDER, Index: i}
			store.addCertificate(item)
		}
		return store, nil
	}
	password, _ := passwordFor(options, PasswordRequest{Format: FormatDER, Purpose: PasswordPurposePrivateKey})
	key, err := parsePrivateKey(data, password)
	if err != nil {
		return nil, errx.Wrap(ErrInvalidData, "der is not a supported certificate or private key")
	}
	item, err := NewPrivateKey(key)
	if err != nil {
		return nil, err
	}
	item.Source = SourceRef{Format: FormatDER}
	store.addPrivateKey(item)
	return store, nil
}
