package certkit

import (
	"time"

	"github.com/emmansun/gmsm/smx509"
)

// VerifyOptions 配置证书链、主机名和验证时间。
type VerifyOptions struct {
	Roots         *TrustStore
	Intermediates []*smx509.Certificate
	DNSName       string
	CurrentTime   time.Time
	KeyUsages     []smx509.ExtKeyUsage
}

// VerifyResult 保存证书链和主机名验证结果。
type VerifyResult struct {
	Trusted       bool
	HostnameValid bool
	Chains        [][]*smx509.Certificate
	Error         error
}

// VerifyCertificate 使用指定信任根和中间证书验证证书。
func VerifyCertificate(cert *smx509.Certificate, options VerifyOptions) VerifyResult {
	result := VerifyResult{HostnameValid: options.DNSName == ""}
	if cert == nil {
		result.Error = ErrNoCertificate
		return result
	}
	if options.DNSName != "" {
		result.HostnameValid = cert.VerifyHostname(options.DNSName) == nil
	}
	intermediates := smx509.NewCertPool()
	for _, intermediate := range options.Intermediates {
		intermediates.AddCert(intermediate)
	}
	verifyOptions := smx509.VerifyOptions{
		Intermediates: intermediates,
		DNSName:       options.DNSName,
		CurrentTime:   options.CurrentTime,
		KeyUsages:     options.KeyUsages,
	}
	var chains [][]*smx509.Certificate
	var err error
	if options.Roots == nil {
		chains, err = cert.Verify(verifyOptions)
	} else {
		chains, err = options.Roots.verify(cert, verifyOptions)
	}
	result.Chains = chains
	result.Trusted = err == nil
	result.Error = err
	return result
}
