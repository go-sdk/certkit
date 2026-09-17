package certkit

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

// TLSVersion 表示需要单独探测的 TLS 协议版本。
type TLSVersion uint16

const (
	TLS10 TLSVersion = tls.VersionTLS10
	TLS11 TLSVersion = tls.VersionTLS11
	TLS12 TLSVersion = tls.VersionTLS12
	TLS13 TLSVersion = tls.VersionTLS13
)

// String 返回面向报告展示的 TLS 版本名称。
func (v TLSVersion) String() string {
	switch v {
	case TLS10:
		return "TLS 1.0"
	case TLS11:
		return "TLS 1.1"
	case TLS12:
		return "TLS 1.2"
	case TLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

// TLSOptions 配置 SNI、协议版本、信任根和连接参数。
type TLSOptions struct {
	ServerName   string
	Versions     []TLSVersion
	Roots        *TrustStore
	Dialer       *net.Dialer
	CipherSuites []uint16
	NextProtos   []string
	CurrentTime  time.Time
}

// TLSFailureStage 表示 TLS 探测失败发生的阶段。
type TLSFailureStage string

const (
	TLSFailureDial      TLSFailureStage = "dial"
	TLSFailureHandshake TLSFailureStage = "handshake"
	TLSFailureParse     TLSFailureStage = "certificate_parse"
)

// TLSFailure 保存单个 TLS 版本的失败阶段和错误信息。
type TLSFailure struct {
	Stage   TLSFailureStage
	Message string
}

// ChainValidation 保存主机名、信任链和服务端链完整性判断。
type ChainValidation struct {
	HostnameValid       bool
	Trusted             bool
	ServedChainComplete bool
	ContainsRoot        bool
	MissingIssuers      []string
	CompletableViaAIA   bool
	Error               error
}

// TLSVersionResult 保存单个 TLS 版本的握手和证书验证结果。
type TLSVersionResult struct {
	Version            TLSVersion
	HandshakeSucceeded bool
	NegotiatedVersion  uint16
	CipherSuite        uint16
	CipherSuiteName    string
	ALPN               string
	PeerCertificates   *Store
	Validation         ChainValidation
	StapledOCSP        *OCSPResult
	StapledOCSPError   error
	Failure            *TLSFailure
}

// TLSReport 保存目标地址在各 TLS 版本下的独立探测结果。
type TLSReport struct {
	Address    string
	ServerName string
	Versions   []TLSVersionResult
}

// InspectTLS 对每个指定 TLS 版本建立独立连接并验证服务端证书。
func InspectTLS(ctx context.Context, address string, options TLSOptions) (*TLSReport, error) {
	address, host, err := normalizeTLSAddress(address)
	if err != nil {
		return nil, err
	}
	serverName := strings.TrimSpace(options.ServerName)
	if serverName == "" {
		serverName = host
	}
	versions := options.Versions
	if len(versions) == 0 {
		versions = []TLSVersion{TLS10, TLS11, TLS12, TLS13}
	}
	if options.Roots == nil {
		options.Roots, err = SystemRoots()
		if err != nil {
			return nil, err
		}
	}
	report := &TLSReport{Address: address, ServerName: serverName, Versions: make([]TLSVersionResult, 0, len(versions))}
	for _, version := range versions {
		if version < TLS10 || version > TLS13 {
			return nil, errx.Wrapf(ErrInvalidData, "unsupported tls version 0x%x", uint16(version))
		}
		report.Versions = append(report.Versions, inspectTLSVersion(ctx, address, serverName, version, options))
	}
	return report, nil
}

func inspectTLSVersion(ctx context.Context, address, serverName string, version TLSVersion, options TLSOptions) TLSVersionResult {
	result := TLSVersionResult{Version: version}
	dialer := options.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}
	rawConnection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Failure = &TLSFailure{Stage: TLSFailureDial, Message: err.Error()}
		return result
	}
	defer func() { _ = rawConnection.Close() }()
	config := &tls.Config{
		MinVersion:         uint16(version),
		MaxVersion:         uint16(version),
		ServerName:         serverName,
		InsecureSkipVerify: true,
		CipherSuites:       append([]uint16(nil), options.CipherSuites...),
		NextProtos:         append([]string(nil), options.NextProtos...),
	}
	connection := tls.Client(rawConnection, config)
	if err := connection.HandshakeContext(ctx); err != nil {
		result.Failure = &TLSFailure{Stage: TLSFailureHandshake, Message: err.Error()}
		return result
	}
	state := connection.ConnectionState()
	result.HandshakeSucceeded = true
	result.NegotiatedVersion = state.Version
	result.CipherSuite = state.CipherSuite
	result.CipherSuiteName = tls.CipherSuiteName(state.CipherSuite)
	result.ALPN = state.NegotiatedProtocol
	store := NewStore()
	store.Source = SourceInfo{Format: FormatDER, Encoding: EncodingDER, IntegrityVerified: true}
	for i, standardCert := range state.PeerCertificates {
		cert, parseErr := smx509.ParseCertificate(standardCert.Raw)
		if parseErr != nil {
			result.Failure = &TLSFailure{Stage: TLSFailureParse, Message: parseErr.Error()}
			return result
		}
		item, _ := NewCertificate(cert)
		item.Source = SourceRef{Format: FormatDER, Index: i}
		store.addCertificate(item)
	}
	result.PeerCertificates = store
	result.Validation = validateTLSChain(store, serverName, options)
	if len(state.OCSPResponse) > 0 && len(store.Certificates) > 1 {
		result.StapledOCSP, result.StapledOCSPError = CheckOCSP(store.Certificates[0].Certificate, store.Certificates[1].Certificate, state.OCSPResponse, OCSPOptions{CurrentTime: options.CurrentTime})
	}
	return result
}

func validateTLSChain(store *Store, serverName string, options TLSOptions) ChainValidation {
	result := ChainValidation{}
	if store == nil || len(store.Certificates) == 0 {
		result.Error = ErrNoCertificate
		return result
	}
	leaf := store.Certificates[0].Certificate
	result.HostnameValid = leaf.VerifyHostname(serverName) == nil
	intermediates := make([]*smx509.Certificate, 0, len(store.Certificates)-1)
	for _, cert := range store.Certificates[1:] {
		intermediates = append(intermediates, cert.Certificate)
		if cert.Role == CertificateRoleRoot {
			result.ContainsRoot = true
		}
	}
	verifyOptions := VerifyOptions{
		Roots:         options.Roots,
		Intermediates: intermediates,
		DNSName:       serverName,
		CurrentTime:   options.CurrentTime,
		KeyUsages:     []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
	}
	verification := VerifyCertificate(leaf, verifyOptions)
	result.Trusted = verification.Trusted
	result.ServedChainComplete = verification.Trusted
	result.Error = verification.Error
	if !verification.Trusted {
		last := leaf
		if len(intermediates) > 0 {
			last = intermediates[len(intermediates)-1]
		}
		result.MissingIssuers = append(result.MissingIssuers, last.Issuer.String())
		result.CompletableViaAIA = len(last.IssuingCertificateURL) > 0
	}
	return result
}

func normalizeTLSAddress(address string) (string, string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", "", errx.Wrap(ErrInvalidData, "tls address must not be empty")
	}
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		if host == "" || port == "" {
			return "", "", errx.Wrap(ErrInvalidData, "tls address host and port are required")
		}
		return address, strings.Trim(host, "[]"), nil
	}
	if strings.Contains(address, ":") && net.ParseIP(strings.Trim(address, "[]")) == nil {
		return "", "", errx.Wrap(err, "parse tls address")
	}
	host = strings.Trim(address, "[]")
	return net.JoinHostPort(host, "443"), host, nil
}
