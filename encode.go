package certkit

import (
	"strings"

	"github.com/go-sdk/core/errx"
)

// PKCS12Profile 选择 PKCS12 的算法兼容配置。
type PKCS12Profile string

const (
	PKCS12ProfileModern  PKCS12Profile = "modern"
	PKCS12ProfileLegacy  PKCS12Profile = "legacy"
	PKCS12ProfileShangMi PKCS12Profile = "shangmi"
)

// EncodeOptions 配置目标格式的密码、alias 和有损转换策略。
type EncodeOptions struct {
	Password             []byte
	KeyPassword          []byte
	KeyPasswords         map[string][]byte
	Alias                string
	Aliases              map[string]string
	AllowLossy           bool
	EncryptPEMPrivateKey bool
	PKCS12Profile        PKCS12Profile
}

// ConversionReport 描述编码结果和被丢弃的对象。
type ConversionReport struct {
	Format                Format
	Aliases               []string
	CertificatesWritten   int
	PrivateKeysWritten    int
	DiscardedCertificates int
	DiscardedPrivateKeys  int
	Warnings              []string
}

// Encode 将 Store 编码为指定格式，并返回转换报告。
func (s *Store) Encode(format Format, options EncodeOptions) ([]byte, *ConversionReport, error) {
	if s == nil {
		return nil, nil, errx.Wrap(ErrInvalidData, "store is nil")
	}
	report := &ConversionReport{Format: format}
	if s.hasUnavailablePrivateKeys() && !options.AllowLossy {
		return nil, report, errx.Wrap(ErrLossyConversion, "store contains unavailable private keys")
	}
	var data []byte
	var err error
	switch format {
	case FormatPEM:
		data, err = s.encodePEM(options, report)
	case FormatDER:
		data, err = s.encodeDER(options, report)
	case FormatPKCS7:
		data, err = s.encodePKCS7(options, report)
	case FormatPKCS12:
		data, err = s.encodePKCS12(options, report)
	case FormatJKS:
		data, err = s.encodeJKS(options, report)
	case FormatJCEKS, FormatBKS:
		err = errx.Wrapf(ErrUnsupportedFormat, "%s is not supported", format)
	default:
		err = errx.Wrapf(ErrUnknownFormat, "format %q", format)
	}
	return data, report, err
}

func (s *Store) privateKeyEntries(alias string) []*Entry {
	entries := make([]*Entry, 0)
	for _, entry := range s.Entries {
		if entry.PrivateKey == nil {
			continue
		}
		if alias == "" || strings.EqualFold(entry.Alias, alias) {
			entries = append(entries, entry)
		}
	}
	return entries
}

func (s *Store) hasUnavailablePrivateKeys() bool {
	for _, entry := range s.Entries {
		if entry.PrivateKeyStatus == PrivateKeyStatusUnavailable {
			return true
		}
	}
	return false
}

func isSyntheticKeyAlias(entry *Entry) bool {
	return entry.PrivateKey != nil && entry.Alias == "key-"+entry.PrivateKey.ID[:12]
}
