package certkit

import (
	"bytes"
	"encoding/pem"

	"github.com/emmansun/gmsm/pkcs8"
	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

func (s *Store) encodePEM(options EncodeOptions, report *ConversionReport) ([]byte, error) {
	var output bytes.Buffer
	for _, cert := range s.Certificates {
		if err := pem.Encode(&output, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate.Raw}); err != nil {
			return nil, errx.Wrap(err, "encode pem certificate")
		}
		report.CertificatesWritten++
	}
	for _, key := range s.PrivateKeys {
		der, err := smx509.MarshalPKCS8PrivateKey(key.Signer)
		if err != nil {
			return nil, errx.Wrap(err, "marshal pem private key")
		}
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
		if options.EncryptPEMPrivateKey {
			if len(options.Password) == 0 {
				return nil, ErrPassword
			}
			der, err = pkcs8.MarshalPrivateKey(key.Signer, options.Password, nil)
			if err != nil {
				return nil, errx.Wrap(err, "encrypt pem private key")
			}
			block = &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}
		}
		if err := pem.Encode(&output, block); err != nil {
			return nil, errx.Wrap(err, "encode pem private key")
		}
		report.PrivateKeysWritten++
	}
	if output.Len() == 0 {
		return nil, errx.Wrap(ErrInvalidData, "store is empty")
	}
	return output.Bytes(), nil
}
