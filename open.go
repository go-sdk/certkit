package certkit

import (
	"bytes"
	"strings"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

const (
	defaultMaxInputSize    = 32 << 20
	defaultMaxCertificates = 4096
	defaultMaxPrivateKeys  = 256
)

// PasswordPurpose 表示密码用于容器还是独立私钥。
type PasswordPurpose string

const (
	PasswordPurposeContainer  PasswordPurpose = "container"
	PasswordPurposePrivateKey PasswordPurpose = "private_key"
)

// PasswordRequest 描述密码提供器当前需要的格式、alias 和用途。
type PasswordRequest struct {
	Format  Format
	Alias   string
	Purpose PasswordPurpose
}

// PasswordProvider 根据解析上下文按需返回密码。
type PasswordProvider func(PasswordRequest) ([]byte, error)

// OpenOptions 配置输入格式、密码来源和解析资源上限。
type OpenOptions struct {
	Format                    Format
	Password                  []byte
	KeyPasswords              map[string][]byte
	PasswordProvider          PasswordProvider
	DisableJKSDefaultPassword bool
	MaxInputSize              int
	MaxCertificates           int
	MaxPrivateKeys            int
}

// MergeReport 记录 Store.Add 实际新增的对象数量。
type MergeReport struct {
	CertificatesAdded int
	PrivateKeysAdded  int
	EntriesAdded      int
}

// Open 根据内容或显式格式解析证书、私钥和密钥库。
func Open(data []byte, options OpenOptions) (*Store, error) {
	options = normalizeOpenOptions(options)
	if len(data) == 0 {
		return nil, errx.Wrap(ErrInvalidData, "input is empty")
	}
	if len(data) > options.MaxInputSize {
		return nil, errx.Wrapf(ErrInvalidData, "input exceeds %d bytes", options.MaxInputSize)
	}
	format := options.Format
	if format == "" || format == FormatAuto {
		detection, err := Detect(data)
		if err != nil {
			return nil, err
		}
		format = detection.Format
	}
	var store *Store
	var err error
	switch format {
	case FormatPEM:
		store, err = openPEM(data, options)
	case FormatDER:
		store, err = openDER(data, options)
	case FormatPKCS7:
		store, err = openPKCS7(unwrapPEM(data), options)
	case FormatPKCS12:
		store, err = openPKCS12(unwrapPEM(data), options)
	case FormatJKS:
		store, err = openJKS(data, options)
	case FormatJCEKS, FormatBKS:
		return nil, errx.Wrapf(ErrUnsupportedFormat, "%s is not supported", format)
	default:
		return nil, errx.Wrapf(ErrUnknownFormat, "format %q", format)
	}
	if store != nil {
		reconcileEntries(store)
		if limitErr := validateStoreLimits(store, options); limitErr != nil {
			return nil, limitErr
		}
	}
	return store, err
}

// Add 解析输入并将对象合并到当前 Store。
func (s *Store) Add(data []byte, options OpenOptions) (*MergeReport, error) {
	other, openErr := Open(data, options)
	if other == nil {
		return nil, openErr
	}
	for _, entry := range other.Entries {
		if s.entryByAlias(entry.Alias) != nil {
			return nil, errx.Wrapf(ErrAliasConflict, "alias %q", entry.Alias)
		}
	}
	report := &MergeReport{}
	for _, cert := range other.Certificates {
		if s.certificateByID(cert.ID) == nil {
			s.Certificates = append(s.Certificates, cert)
			report.CertificatesAdded++
		}
	}
	for _, key := range other.PrivateKeys {
		if s.privateKeyByID(key.ID) == nil {
			s.PrivateKeys = append(s.PrivateKeys, key)
			report.PrivateKeysAdded++
		}
	}
	for _, entry := range other.Entries {
		entry.Chain = s.canonicalCertificates(entry.Chain)
		if entry.PrivateKey != nil {
			entry.PrivateKey = s.privateKeyByID(entry.PrivateKey.ID)
		}
		s.Entries = append(s.Entries, entry)
		report.EntriesAdded++
	}
	s.Diagnostics = append(s.Diagnostics, other.Diagnostics...)
	return report, openErr
}

func normalizeOpenOptions(options OpenOptions) OpenOptions {
	if options.Format == "" {
		options.Format = FormatAuto
	}
	if options.MaxInputSize <= 0 {
		options.MaxInputSize = defaultMaxInputSize
	}
	if options.MaxCertificates <= 0 {
		options.MaxCertificates = defaultMaxCertificates
	}
	if options.MaxPrivateKeys <= 0 {
		options.MaxPrivateKeys = defaultMaxPrivateKeys
	}
	return options
}

func validateStoreLimits(store *Store, options OpenOptions) error {
	if len(store.Certificates) > options.MaxCertificates {
		return errx.Wrapf(ErrInvalidData, "certificate count exceeds %d", options.MaxCertificates)
	}
	if len(store.PrivateKeys) > options.MaxPrivateKeys {
		return errx.Wrapf(ErrInvalidData, "private key count exceeds %d", options.MaxPrivateKeys)
	}
	return nil
}

func reconcileEntries(store *Store) {
	for _, entry := range store.Entries {
		if entry.PrivateKey == nil {
			continue
		}
		if len(entry.Chain) == 0 {
			for _, cert := range store.Certificates {
				if publicKeysEqual(entry.PrivateKey.Signer.Public(), cert.Certificate.PublicKey) {
					entry.Chain = buildCertificateChain(cert, store.Certificates)
					break
				}
			}
		} else {
			entry.Chain = buildCertificateChain(entry.Chain[0], store.Certificates)
		}
	}
	for _, key := range store.PrivateKeys {
		found := false
		for _, entry := range store.Entries {
			if entry.PrivateKey != nil && entry.PrivateKey.ID == key.ID {
				found = true
				break
			}
		}
		if found {
			continue
		}
		entry := &Entry{Alias: "key-" + key.ID[:12], PrivateKey: key, PrivateKeyStatus: PrivateKeyStatusAvailable}
		for _, cert := range store.Certificates {
			if publicKeysEqual(key.Signer.Public(), cert.Certificate.PublicKey) {
				entry.Chain = buildCertificateChain(cert, store.Certificates)
				break
			}
		}
		store.Entries = append(store.Entries, entry)
	}
}

func buildCertificateChain(leaf *Certificate, certificates []*Certificate) []*Certificate {
	if leaf == nil {
		return nil
	}
	chain := []*Certificate{leaf}
	seen := map[string]struct{}{leaf.ID: {}}
	current := leaf
	for current.Role != CertificateRoleRoot {
		var parent *Certificate
		for _, candidate := range certificates {
			if _, exists := seen[candidate.ID]; exists || !candidate.Certificate.IsCA {
				continue
			}
			if !bytes.Equal(current.Certificate.RawIssuer, candidate.Certificate.RawSubject) {
				continue
			}
			if len(current.Certificate.AuthorityKeyId) > 0 && len(candidate.Certificate.SubjectKeyId) > 0 && !bytes.Equal(current.Certificate.AuthorityKeyId, candidate.Certificate.SubjectKeyId) {
				continue
			}
			if current.Certificate.CheckSignatureFrom(candidate.Certificate) == nil {
				parent = candidate
				break
			}
		}
		if parent == nil {
			break
		}
		chain = append(chain, parent)
		seen[parent.ID] = struct{}{}
		current = parent
	}
	return chain
}

func mergeStoreObjects(target, source *Store) {
	for _, cert := range source.Certificates {
		target.addCertificate(cert)
	}
	for _, key := range source.PrivateKeys {
		target.addPrivateKey(key)
	}
	target.Diagnostics = append(target.Diagnostics, source.Diagnostics...)
}

func defaultAlias(cert *smx509.Certificate) string {
	if cert != nil && strings.TrimSpace(cert.Subject.CommonName) != "" {
		return cert.Subject.CommonName
	}
	return "mykey"
}
