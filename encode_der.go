package certkit

import (
	"bytes"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

func (s *Store) encodeDER(options EncodeOptions, report *ConversionReport) ([]byte, error) {
	objects := len(s.Certificates) + len(s.PrivateKeys)
	if objects == 0 {
		return nil, errx.Wrap(ErrInvalidData, "store is empty")
	}
	if objects > 1 && !options.AllowLossy {
		return nil, ErrLossyConversion
	}
	if len(s.Certificates) > 0 {
		report.CertificatesWritten = 1
		report.DiscardedCertificates = len(s.Certificates) - 1
		report.DiscardedPrivateKeys = len(s.PrivateKeys)
		return bytes.Clone(s.Certificates[0].Certificate.Raw), nil
	}
	der, err := smx509.MarshalPKCS8PrivateKey(s.PrivateKeys[0].Signer)
	if err != nil {
		return nil, errx.Wrap(err, "marshal der private key")
	}
	report.PrivateKeysWritten = 1
	report.DiscardedPrivateKeys = len(s.PrivateKeys) - 1
	return der, nil
}
