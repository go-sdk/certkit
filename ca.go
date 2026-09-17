package certkit

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

// RootCAOptions 配置自签根 CA 的主题、有效期、路径约束和密钥。
type RootCAOptions struct {
	Alias          string
	Subject        pkix.Name
	NotBefore      time.Time
	NotAfter       time.Time
	ValidFor       time.Duration
	MaxPathLen     int
	MaxPathLenZero bool
	Key            KeyOptions
}

// CertificateOptions 配置 CA 或终端证书的主题、用途、有效期和密钥。
type CertificateOptions struct {
	Alias          string
	Subject        pkix.Name
	NotBefore      time.Time
	NotAfter       time.Time
	ValidFor       time.Duration
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []*url.URL
	IsCA           bool
	MaxPathLen     int
	MaxPathLenZero bool
	KeyUsage       smx509.KeyUsage
	ExtKeyUsage    []smx509.ExtKeyUsage
	SerialNumber   *big.Int
	Key            KeyOptions
}

// CreateRootCA 创建自签根 CA 证书及其私钥。
func CreateRootCA(options RootCAOptions) (*Entry, error) {
	key, err := GeneratePrivateKey(options.Key)
	if err != nil {
		return nil, err
	}
	notBefore, notAfter, err := certificateValidity(options.NotBefore, options.NotAfter, options.ValidFor, 10*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	maxPathLen := options.MaxPathLen
	if maxPathLen == 0 && !options.MaxPathLenZero {
		maxPathLen = -1
	}
	template := &smx509.Certificate{
		SerialNumber:          serial,
		Subject:               options.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign | smx509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        options.MaxPathLenZero,
		SubjectKeyId:          ski,
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, errx.Wrap(err, "create root CA certificate")
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		return nil, errx.Wrap(err, "parse root CA certificate")
	}
	return newIssuedEntry(defaultEntryAlias(options.Alias, cert), key, []*smx509.Certificate{cert})
}

// IssueCertificate 使用 CA 生成新私钥并签发证书。
func IssueCertificate(issuer *Entry, options CertificateOptions) (*Entry, error) {
	issuerCert, issuerKey, err := validateIssuer(issuer)
	if err != nil {
		return nil, err
	}
	key, err := GeneratePrivateKey(options.Key)
	if err != nil {
		return nil, err
	}
	defaultValidFor := 397 * 24 * time.Hour
	if options.IsCA {
		defaultValidFor = 5 * 365 * 24 * time.Hour
	}
	notBefore, notAfter, err := certificateValidity(options.NotBefore, options.NotAfter, options.ValidFor, defaultValidFor)
	if err != nil {
		return nil, err
	}
	if notAfter.After(issuerCert.NotAfter) {
		return nil, errx.Wrap(ErrInvalidData, "certificate validity exceeds issuer validity")
	}
	serial := options.SerialNumber
	if serial == nil {
		serial, err = randomSerialNumber()
		if err != nil {
			return nil, err
		}
	}
	ski, err := subjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	keyUsage := options.KeyUsage
	if keyUsage == 0 {
		keyUsage = defaultKeyUsage(key.Public(), options.IsCA)
	}
	extKeyUsage := options.ExtKeyUsage
	if len(extKeyUsage) == 0 && !options.IsCA {
		extKeyUsage = []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth, smx509.ExtKeyUsageClientAuth}
	}
	maxPathLen := options.MaxPathLen
	if options.IsCA && maxPathLen == 0 && !options.MaxPathLenZero {
		maxPathLen = -1
	}
	template := &smx509.Certificate{
		SerialNumber:          serial,
		Subject:               options.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  options.IsCA,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        options.IsCA && options.MaxPathLenZero,
		SubjectKeyId:          ski,
		AuthorityKeyId:        issuerCert.SubjectKeyId,
		DNSNames:              append([]string(nil), options.DNSNames...),
		IPAddresses:           cloneIPs(options.IPAddresses),
		EmailAddresses:        append([]string(nil), options.EmailAddresses...),
		URIs:                  append([]*url.URL(nil), options.URIs...),
	}
	der, err := smx509.CreateCertificate(rand.Reader, template, issuerCert, key.Public(), issuerKey)
	if err != nil {
		return nil, errx.Wrap(err, "issue certificate")
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		return nil, errx.Wrap(err, "parse issued certificate")
	}
	chain := []*smx509.Certificate{cert}
	for _, parent := range issuer.Chain {
		chain = append(chain, parent.Certificate)
	}
	return newIssuedEntry(defaultEntryAlias(options.Alias, cert), key, chain)
}

func newIssuedEntry(alias string, key crypto.Signer, chain []*smx509.Certificate) (*Entry, error) {
	privateKey, err := NewPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certificates := make([]*Certificate, 0, len(chain))
	for _, cert := range chain {
		item, itemErr := NewCertificate(cert)
		if itemErr != nil {
			return nil, itemErr
		}
		certificates = append(certificates, item)
	}
	return &Entry{
		Alias:            alias,
		CreatedAt:        time.Now(),
		PrivateKey:       privateKey,
		PrivateKeyStatus: PrivateKeyStatusAvailable,
		Chain:            certificates,
	}, nil
}

func validateIssuer(issuer *Entry) (*smx509.Certificate, crypto.Signer, error) {
	if issuer == nil || issuer.PrivateKey == nil || len(issuer.Chain) == 0 {
		return nil, nil, errx.Wrap(ErrInvalidData, "issuer certificate and private key are required")
	}
	cert := issuer.Chain[0].Certificate
	if !cert.IsCA || (cert.KeyUsage != 0 && cert.KeyUsage&smx509.KeyUsageCertSign == 0) {
		return nil, nil, errx.Wrap(ErrInvalidData, "issuer is not allowed to sign certificates")
	}
	if !publicKeysEqual(issuer.PrivateKey.Signer.Public(), cert.PublicKey) {
		return nil, nil, ErrKeyMismatch
	}
	return cert, issuer.PrivateKey.Signer, nil
}

func certificateValidity(notBefore, notAfter time.Time, validFor, defaultValidFor time.Duration) (time.Time, time.Time, error) {
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-5 * time.Minute)
	}
	if notAfter.IsZero() {
		if validFor <= 0 {
			validFor = defaultValidFor
		}
		notAfter = notBefore.Add(validFor)
	}
	if !notAfter.After(notBefore) {
		return time.Time{}, time.Time{}, errx.Wrap(ErrInvalidData, "certificate notAfter must be after notBefore")
	}
	return notBefore, notAfter, nil
}

func defaultEntryAlias(alias string, cert *smx509.Certificate) string {
	if strings.TrimSpace(alias) != "" {
		return strings.TrimSpace(alias)
	}
	return defaultAlias(cert)
}
