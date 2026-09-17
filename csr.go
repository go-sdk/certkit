package certkit

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

// CSROptions 配置 PKCS#10 CSR 的主题和 Subject Alternative Name。
type CSROptions struct {
	Subject        pkix.Name
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []*url.URL
}

// CreateCertificateRequest 使用现有私钥创建 DER 编码的 PKCS#10 CSR。
func CreateCertificateRequest(key crypto.Signer, options CSROptions) ([]byte, error) {
	if key == nil {
		return nil, errx.Wrap(ErrInvalidData, "private key is required")
	}
	template := &smx509.CertificateRequest{
		Subject:        options.Subject,
		DNSNames:       append([]string(nil), options.DNSNames...),
		IPAddresses:    cloneIPs(options.IPAddresses),
		EmailAddresses: append([]string(nil), options.EmailAddresses...),
		URIs:           append([]*url.URL(nil), options.URIs...),
	}
	der, err := smx509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, errx.Wrap(err, "create certificate request")
	}
	return der, nil
}

// SignCertificateRequest 验证 PKCS#10 CSR 并使用 CA 签发证书。
func SignCertificateRequest(issuer *Entry, requestData []byte, options CertificateOptions) (*Entry, error) {
	request, err := parseCertificateRequest(requestData)
	if err != nil {
		return nil, err
	}
	if err := request.CheckSignature(); err != nil {
		return nil, errx.Wrap(err, "verify certificate request signature")
	}
	if len(options.Subject.Names) == 0 {
		options.Subject = request.Subject
	}
	if options.DNSNames == nil {
		options.DNSNames = append([]string(nil), request.DNSNames...)
	}
	if options.IPAddresses == nil {
		options.IPAddresses = cloneIPs(request.IPAddresses)
	}
	if options.EmailAddresses == nil {
		options.EmailAddresses = append([]string(nil), request.EmailAddresses...)
	}
	if options.URIs == nil {
		options.URIs = append([]*url.URL(nil), request.URIs...)
	}
	issuerCert, issuerKey, err := validateIssuer(issuer)
	if err != nil {
		return nil, err
	}
	cert, err := issuePublicKey(issuerCert, issuerKey, request.PublicKey, options)
	if err != nil {
		return nil, err
	}
	chain := []*smx509.Certificate{cert}
	for _, parent := range issuer.Chain {
		chain = append(chain, parent.Certificate)
	}
	certificates := make([]*Certificate, 0, len(chain))
	for _, chainCert := range chain {
		item, itemErr := NewCertificate(chainCert)
		if itemErr != nil {
			return nil, itemErr
		}
		certificates = append(certificates, item)
	}
	return &Entry{Alias: defaultEntryAlias(options.Alias, cert), CreatedAt: time.Now(), Chain: certificates}, nil
}

func issuePublicKey(issuerCert *smx509.Certificate, issuerKey crypto.Signer, publicKey any, options CertificateOptions) (*smx509.Certificate, error) {
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
	ski, err := subjectKeyID(publicKey)
	if err != nil {
		return nil, err
	}
	keyUsage := options.KeyUsage
	if keyUsage == 0 {
		keyUsage = defaultKeyUsage(publicKey, options.IsCA)
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
	der, err := smx509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, issuerKey)
	if err != nil {
		return nil, errx.Wrap(err, "issue certificate")
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		return nil, errx.Wrap(err, "parse issued certificate")
	}
	return cert, nil
}

func parseCertificateRequest(data []byte) (*smx509.CertificateRequest, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	request, err := smx509.ParseCertificateRequest(data)
	if err != nil {
		return nil, errx.Wrap(err, "parse certificate request")
	}
	return request, nil
}
