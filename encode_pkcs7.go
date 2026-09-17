package certkit

import (
	"bytes"

	"github.com/emmansun/gmsm/pkcs7"
	"github.com/go-sdk/core/errx"
)

func (s *Store) encodePKCS7(options EncodeOptions, report *ConversionReport) ([]byte, error) {
	if len(s.Certificates) == 0 {
		return nil, ErrNoCertificate
	}
	if len(s.PrivateKeys) > 0 && !options.AllowLossy {
		return nil, ErrLossyConversion
	}
	var certificates bytes.Buffer
	for _, cert := range s.Certificates {
		certificates.Write(cert.Certificate.Raw)
	}
	data, err := pkcs7.DegenerateCertificate(certificates.Bytes())
	if err != nil {
		return nil, errx.Wrap(err, "encode pkcs7")
	}
	report.CertificatesWritten = len(s.Certificates)
	report.DiscardedPrivateKeys = len(s.PrivateKeys)
	return data, nil
}
