package certkit

import (
	"crypto/x509"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
	sslmatepkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/go-sdk/certkit/internal/pkcs12"
)

func (s *Store) encodePKCS12(options EncodeOptions, report *ConversionReport) ([]byte, error) {
	if len(options.Password) == 0 {
		return nil, ErrPassword
	}
	if options.PKCS12Profile != "" && options.PKCS12Profile != PKCS12ProfileModern && options.PKCS12Profile != PKCS12ProfileLegacy && options.PKCS12Profile != PKCS12ProfileShangMi {
		return nil, errx.Wrapf(ErrInvalidData, "unknown pkcs12 profile %q", options.PKCS12Profile)
	}
	entries := s.privateKeyEntries(options.Alias)
	if len(entries) == 0 {
		if len(s.PrivateKeys) > 0 {
			return nil, errx.Wrapf(ErrNoPrivateKey, "private key entry alias %q not found", options.Alias)
		}
		if options.PKCS12Profile == PKCS12ProfileShangMi {
			return s.encodeShangMiPKCS12TrustStore(options, report)
		}
		trustEntries := make([]sslmatepkcs12.TrustStoreEntry, 0, len(s.Certificates))
		for i, cert := range s.Certificates {
			alias := defaultAlias(cert.Certificate)
			if i < len(s.Entries) && s.Entries[i].Alias != "" {
				alias = s.Entries[i].Alias
			}
			standardCert, err := x509.ParseCertificate(cert.Certificate.Raw)
			if err != nil {
				return nil, errx.Wrap(err, "convert pkcs12 trust certificate")
			}
			trustEntries = append(trustEntries, sslmatepkcs12.TrustStoreEntry{Cert: standardCert, FriendlyName: alias})
			report.Aliases = append(report.Aliases, alias)
		}
		encoder := sslmatepkcs12.Modern2026
		if options.PKCS12Profile == PKCS12ProfileLegacy {
			encoder = sslmatepkcs12.Legacy
		}
		data, err := encoder.EncodeTrustStoreEntries(trustEntries, string(options.Password))
		if err != nil {
			return nil, errx.Wrap(err, "encode pkcs12 trust store")
		}
		report.CertificatesWritten = len(s.Certificates)
		return data, nil
	}
	if len(entries) > 1 {
		return nil, errx.Wrap(ErrLossyConversion, "pkcs12 output requires a single private key entry")
	}
	entry := entries[0]
	if len(entry.Chain) == 0 {
		return nil, errx.Wrap(ErrNoCertificate, "private key entry has no certificate")
	}
	if !publicKeysEqual(entry.PrivateKey.Signer.Public(), entry.Chain[0].Certificate.PublicKey) {
		return nil, ErrKeyMismatch
	}
	chain := make([]*smx509.Certificate, 0, len(entry.Chain)-1)
	for _, cert := range entry.Chain[1:] {
		chain = append(chain, cert.Certificate)
	}
	var data []byte
	var err error
	if options.PKCS12Profile == PKCS12ProfileShangMi {
		data, err = pkcs12.ShangMi2024.Encode(entry.PrivateKey.Signer, entry.Chain[0].Certificate, chain, string(options.Password))
	} else {
		standardLeaf, parseErr := x509.ParseCertificate(entry.Chain[0].Certificate.Raw)
		if parseErr != nil {
			return nil, errx.Wrap(parseErr, "convert pkcs12 leaf certificate")
		}
		standardChain := make([]*x509.Certificate, 0, len(chain))
		for _, cert := range chain {
			standardCert, certErr := x509.ParseCertificate(cert.Raw)
			if certErr != nil {
				return nil, errx.Wrap(certErr, "convert pkcs12 ca certificate")
			}
			standardChain = append(standardChain, standardCert)
		}
		encoder := sslmatepkcs12.Modern2026
		if options.PKCS12Profile == PKCS12ProfileLegacy {
			encoder = sslmatepkcs12.Legacy
		}
		data, err = encoder.Encode(entry.PrivateKey.Signer, standardLeaf, standardChain, string(options.Password))
	}
	if err != nil {
		return nil, errx.Wrap(err, "encode pkcs12")
	}
	report.Aliases = append(report.Aliases, entry.Alias)
	report.CertificatesWritten = len(entry.Chain)
	report.PrivateKeysWritten = 1
	report.DiscardedCertificates = len(s.Certificates) - len(entry.Chain)
	report.DiscardedPrivateKeys = len(s.PrivateKeys) - 1
	if (report.DiscardedCertificates > 0 || report.DiscardedPrivateKeys > 0) && !options.AllowLossy {
		return nil, ErrLossyConversion
	}
	return data, nil
}

func (s *Store) encodeShangMiPKCS12TrustStore(options EncodeOptions, report *ConversionReport) ([]byte, error) {
	entries := make([]pkcs12.TrustStoreEntry, 0, len(s.Certificates))
	for i, cert := range s.Certificates {
		alias := defaultAlias(cert.Certificate)
		if i < len(s.Entries) && s.Entries[i].Alias != "" {
			alias = s.Entries[i].Alias
		}
		entries = append(entries, pkcs12.TrustStoreEntry{Cert: cert.Certificate, FriendlyName: alias})
		report.Aliases = append(report.Aliases, alias)
	}
	data, err := pkcs12.ShangMi2024.EncodeTrustStoreEntries(entries, string(options.Password))
	if err != nil {
		return nil, errx.Wrap(err, "encode shangmi pkcs12 trust store")
	}
	report.CertificatesWritten = len(s.Certificates)
	return data, nil
}
