package certkit

import (
	"bytes"
	"context"
	"crypto"
	"io"
	"net/http"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"

	internalocsp "github.com/go-sdk/certkit/internal/ocsp"
)

// OCSPOptions 配置 OCSP 验证时间、哈希算法和网络响应大小限制。
type OCSPOptions struct {
	CurrentTime  time.Time
	MaxClockSkew time.Duration
	Hash         crypto.Hash
	MaxSize      int64
}

// OCSPResult 保存 OCSP 响应中的状态和有效时间。
type OCSPResult struct {
	Status           int
	SerialNumber     string
	ProducedAt       time.Time
	ThisUpdate       time.Time
	NextUpdate       time.Time
	RevokedAt        time.Time
	RevocationReason int
	Fresh            bool
}

// CheckOCSP 在本地解析并验证指定证书的 OCSP 响应。
func CheckOCSP(cert, issuer *smx509.Certificate, data []byte, options OCSPOptions) (*OCSPResult, error) {
	response, err := internalocsp.ParseResponseForCert(data, cert, issuer)
	if err != nil {
		return nil, errx.Wrap(err, "parse ocsp response")
	}
	now := options.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	result := &OCSPResult{
		Status:           response.Status,
		ProducedAt:       response.ProducedAt,
		ThisUpdate:       response.ThisUpdate,
		NextUpdate:       response.NextUpdate,
		RevokedAt:        response.RevokedAt,
		RevocationReason: response.RevocationReason,
	}
	if response.SerialNumber != nil {
		result.SerialNumber = response.SerialNumber.String()
	}
	result.Fresh = !now.Add(options.MaxClockSkew).Before(response.ThisUpdate) && (response.NextUpdate.IsZero() || !now.Add(-options.MaxClockSkew).After(response.NextUpdate))
	return result, nil
}

// FetchAndCheckOCSP 向证书首个 OCSP 地址发起请求并验证响应。
func FetchAndCheckOCSP(ctx context.Context, client *http.Client, cert, issuer *smx509.Certificate, options OCSPOptions) (*OCSPResult, error) {
	if cert == nil || len(cert.OCSPServer) == 0 {
		return nil, errx.Wrap(ErrInvalidData, "certificate has no ocsp responder")
	}
	hash := options.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}
	requestData, err := internalocsp.CreateRequest(cert, issuer, hash)
	if err != nil {
		return nil, errx.Wrap(err, "create ocsp request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cert.OCSPServer[0], bytes.NewReader(requestData))
	if err != nil {
		return nil, errx.Wrap(err, "create ocsp http request")
	}
	request.Header.Set("Content-Type", "application/ocsp-request")
	request.Header.Set("Accept", "application/ocsp-response")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errx.Wrap(err, "fetch ocsp response")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errx.Newf("fetch ocsp response: unexpected http status %d", response.StatusCode)
	}
	maxSize := options.MaxSize
	if maxSize <= 0 {
		maxSize = 1 << 20
	}
	responseData, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if err != nil {
		return nil, errx.Wrap(err, "read ocsp response")
	}
	if int64(len(responseData)) > maxSize {
		return nil, errx.Wrap(ErrInvalidData, "ocsp response is too large")
	}
	return CheckOCSP(cert, issuer, responseData, options)
}
