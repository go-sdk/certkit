package certkit

import (
	"github.com/emmansun/gmsm/pkcs7"
	"github.com/go-sdk/core/errx"

	"github.com/go-sdk/certkit/internal/ber"
)

func openPKCS7(data []byte, _ OpenOptions) (store *Store, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			store = nil
			err = errx.Wrapf(ErrInvalidData, "parse pkcs7: %v", recovered)
		}
	}()
	data, err = ber.ToDER(data)
	if err != nil {
		return nil, errx.Wrap(err, "normalize pkcs7 ber")
	}
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, errx.Wrap(err, "parse pkcs7")
	}
	store = NewStore()
	store.Source = SourceInfo{Format: FormatPKCS7, Encoding: EncodingDER, IntegrityVerified: true}
	for i, cert := range p7.Certificates {
		item, itemErr := NewCertificate(cert)
		if itemErr != nil {
			return nil, itemErr
		}
		item.Source = SourceRef{Format: FormatPKCS7, Index: i}
		store.addCertificate(item)
	}
	if len(store.Certificates) == 0 {
		return nil, errx.Wrap(ErrNoCertificate, "pkcs7 contains no certificates")
	}
	return store, nil
}
