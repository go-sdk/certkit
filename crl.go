package certkit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

const defaultMaxCRLSize = 16 << 20

// RevokedCertificate 描述写入 CRL 的吊销证书条目。
type RevokedCertificate struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	ReasonCode     int
}

// CreateCRLOptions 配置 CRL 编号、有效期和吊销条目。
type CreateCRLOptions struct {
	Number       *big.Int
	ThisUpdate   time.Time
	NextUpdate   time.Time
	ValidFor     time.Duration
	Certificates []RevokedCertificate
}

// CRLOptions 配置 CRL 验证时间、时钟偏差和网络响应大小限制。
type CRLOptions struct {
	CurrentTime  time.Time
	MaxClockSkew time.Duration
	MaxSize      int64
}

// CRLResult 保存 CRL 签名、时效和证书吊销状态。
type CRLResult struct {
	Revoked        bool
	ReasonCode     int
	RevocationTime time.Time
	ThisUpdate     time.Time
	NextUpdate     time.Time
	SignatureValid bool
	Fresh          bool
}

// CreateCRL 使用 CA 证书及私钥创建 DER 编码的 CRL。
func CreateCRL(issuer *Entry, options CreateCRLOptions) ([]byte, error) {
	issuerCert, issuerKey, err := validateIssuer(issuer)
	if err != nil {
		return nil, err
	}
	thisUpdate := options.ThisUpdate
	if thisUpdate.IsZero() {
		thisUpdate = time.Now().Add(-time.Minute)
	}
	nextUpdate := options.NextUpdate
	if nextUpdate.IsZero() {
		validFor := options.ValidFor
		if validFor <= 0 {
			validFor = 7 * 24 * time.Hour
		}
		nextUpdate = thisUpdate.Add(validFor)
	}
	if !nextUpdate.After(thisUpdate) {
		return nil, errx.Wrap(ErrInvalidData, "crl nextUpdate must be after thisUpdate")
	}
	number := options.Number
	if number == nil {
		number = big.NewInt(1)
	}
	entries := make([]smx509.RevocationListEntry, 0, len(options.Certificates))
	for _, revoked := range options.Certificates {
		if revoked.SerialNumber == nil || revoked.RevocationTime.IsZero() {
			return nil, errx.Wrap(ErrInvalidData, "revoked certificate serial number and time are required")
		}
		entries = append(entries, smx509.RevocationListEntry{SerialNumber: revoked.SerialNumber, RevocationTime: revoked.RevocationTime, ReasonCode: revoked.ReasonCode})
	}
	template := &smx509.RevocationList{
		Number:                    number,
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := smx509.CreateRevocationList(rand.Reader, template, issuerCert, issuerKey)
	if err != nil {
		return nil, errx.Wrap(err, "create crl")
	}
	return der, nil
}

// CheckCRL 在本地解析并验证 CRL，不访问网络。
func CheckCRL(cert, issuer *smx509.Certificate, data []byte, options CRLOptions) (*CRLResult, error) {
	if cert == nil || issuer == nil {
		return nil, errx.Wrap(ErrInvalidData, "certificate and issuer are required")
	}
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	list, err := smx509.ParseRevocationList(data)
	if err != nil {
		return nil, errx.Wrap(err, "parse crl")
	}
	if !bytes.Equal(list.RawIssuer, issuer.RawSubject) {
		return nil, errx.Wrap(ErrInvalidData, "crl issuer does not match certificate issuer")
	}
	if len(list.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId) {
		return nil, errx.Wrap(ErrInvalidData, "crl authority key identifier does not match issuer")
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&smx509.KeyUsageCRLSign == 0 {
		return nil, errx.Wrap(ErrInvalidData, "issuer is not allowed to sign crls")
	}
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return nil, errx.Wrap(err, "verify crl signature")
	}
	now := options.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	result := &CRLResult{ThisUpdate: list.ThisUpdate, NextUpdate: list.NextUpdate, SignatureValid: true}
	result.Fresh = !now.Add(options.MaxClockSkew).Before(list.ThisUpdate) && (list.NextUpdate.IsZero() || !now.Add(-options.MaxClockSkew).After(list.NextUpdate))
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			result.Revoked = true
			result.ReasonCode = entry.ReasonCode
			result.RevocationTime = entry.RevocationTime
			break
		}
	}
	return result, nil
}

// FetchAndCheckCRL 获取证书首个 CRL 地址并验证响应。
func FetchAndCheckCRL(ctx context.Context, client *http.Client, cert, issuer *smx509.Certificate, options CRLOptions) (*CRLResult, error) {
	if cert == nil || len(cert.CRLDistributionPoints) == 0 {
		return nil, errx.Wrap(ErrInvalidData, "certificate has no crl distribution point")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, cert.CRLDistributionPoints[0], nil)
	if err != nil {
		return nil, errx.Wrap(err, "create crl request")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errx.Wrap(err, "fetch crl")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errx.Newf("fetch crl: unexpected http status %d", response.StatusCode)
	}
	maxSize := options.MaxSize
	if maxSize <= 0 {
		maxSize = defaultMaxCRLSize
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if err != nil {
		return nil, errx.Wrap(err, "read crl response")
	}
	if int64(len(data)) > maxSize {
		return nil, errx.Wrap(ErrInvalidData, "crl response is too large")
	}
	return CheckCRL(cert, issuer, data, options)
}
