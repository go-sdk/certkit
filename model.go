package certkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

// DiagnosticLevel 表示解析或转换诊断的严重程度。
type DiagnosticLevel string

const (
	DiagnosticInfo    DiagnosticLevel = "info"
	DiagnosticWarning DiagnosticLevel = "warning"
	DiagnosticError   DiagnosticLevel = "error"
)

// Diagnostic 保存未中断处理流程的诊断信息。
type Diagnostic struct {
	Level   DiagnosticLevel
	Code    string
	Message string
	Alias   string
}

// SourceInfo 描述 Store 的来源格式和完整性状态。
type SourceInfo struct {
	Format            Format
	Encoding          Encoding
	IntegrityVerified bool
}

// SourceRef 记录证书或私钥在来源容器中的位置。
type SourceRef struct {
	Format Format
	Alias  string
	Index  int
}

// CertificateRole 表示证书在链中的角色。
type CertificateRole string

const (
	CertificateRoleUnknown      CertificateRole = "unknown"
	CertificateRoleLeaf         CertificateRole = "leaf"
	CertificateRoleIntermediate CertificateRole = "intermediate"
	CertificateRoleRoot         CertificateRole = "root"
)

// Certificate 保存规范化证书及其稳定标识和来源。
type Certificate struct {
	ID          string
	Certificate *smx509.Certificate
	Role        CertificateRole
	Source      SourceRef
}

// KeyAlgorithm 表示证书或私钥使用的公钥算法。
type KeyAlgorithm string

const (
	KeyAlgorithmUnknown KeyAlgorithm = "unknown"
	KeyAlgorithmRSA     KeyAlgorithm = "rsa"
	KeyAlgorithmEC      KeyAlgorithm = "ec"
	KeyAlgorithmSM2     KeyAlgorithm = "sm2"
)

// PrivateKey 保存可签名私钥及其稳定公钥标识。
type PrivateKey struct {
	ID         string
	Signer     crypto.Signer
	Algorithm  KeyAlgorithm
	Exportable bool
	Source     SourceRef
}

// PrivateKeyStatus 表示密钥库条目的私钥是否可用。
type PrivateKeyStatus string

const (
	PrivateKeyStatusAvailable   PrivateKeyStatus = "available"
	PrivateKeyStatusUnavailable PrivateKeyStatus = "unavailable"
)

// Entry 保存 alias、私钥和有序证书链之间的关系。
type Entry struct {
	Alias            string
	CreatedAt        time.Time
	PrivateKey       *PrivateKey
	PrivateKeyStatus PrivateKeyStatus
	Chain            []*Certificate
	Trusted          bool
}

// Store 统一保存解析后的条目、证书、私钥和诊断信息。
type Store struct {
	Source       SourceInfo
	Entries      []*Entry
	Certificates []*Certificate
	PrivateKeys  []*PrivateKey
	Diagnostics  []Diagnostic
}

// NewStore 创建空的内存证书库。
func NewStore() *Store {
	return &Store{Source: SourceInfo{Format: FormatUnknown, Encoding: EncodingUnknown, IntegrityVerified: true}}
}

// NewCertificate 将已解析证书规范化为 Store 使用的模型。
func NewCertificate(cert *smx509.Certificate) (*Certificate, error) {
	if cert == nil || len(cert.Raw) == 0 {
		return nil, errx.Wrap(ErrInvalidData, "certificate is empty")
	}
	sum := sha256.Sum256(cert.Raw)
	return &Certificate{ID: hex.EncodeToString(sum[:]), Certificate: cert, Role: certificateRole(cert)}, nil
}

// NewPrivateKey 将签名私钥规范化为 Store 使用的模型。
func NewPrivateKey(key crypto.Signer) (*PrivateKey, error) {
	if key == nil {
		return nil, errx.Wrap(ErrInvalidData, "private key is empty")
	}
	der, err := smx509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, errx.Wrap(err, "marshal public key")
	}
	sum := sha256.Sum256(der)
	return &PrivateKey{
		ID:         hex.EncodeToString(sum[:]),
		Signer:     key,
		Algorithm:  keyAlgorithm(key),
		Exportable: true,
	}, nil
}

// AddCertificate 向 Store 添加证书并重新匹配已有条目。
func (s *Store) AddCertificate(cert *smx509.Certificate) error {
	item, err := NewCertificate(cert)
	if err != nil {
		return err
	}
	s.addCertificate(item)
	reconcileEntries(s)
	return nil
}

// AddPrivateKey 向 Store 添加私钥并重新匹配已有条目。
func (s *Store) AddPrivateKey(key crypto.Signer) error {
	item, err := NewPrivateKey(key)
	if err != nil {
		return err
	}
	s.addPrivateKey(item)
	reconcileEntries(s)
	return nil
}

// AddKeyPair 使用指定 alias 添加私钥及其有序证书链。
func (s *Store) AddKeyPair(alias string, key crypto.Signer, chain ...*smx509.Certificate) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return errx.Wrap(ErrInvalidData, "alias must not be empty")
	}
	if s.entryByAlias(alias) != nil {
		return errx.Wrapf(ErrAliasConflict, "alias %q", alias)
	}
	privateKey, err := NewPrivateKey(key)
	if err != nil {
		return err
	}
	certificates := make([]*Certificate, 0, len(chain))
	for _, cert := range chain {
		item, itemErr := NewCertificate(cert)
		if itemErr != nil {
			return itemErr
		}
		certificates = append(certificates, item)
	}
	if len(certificates) > 0 && !publicKeysEqual(privateKey.Signer.Public(), certificates[0].Certificate.PublicKey) {
		return ErrKeyMismatch
	}
	for _, cert := range certificates {
		s.addCertificate(cert)
	}
	s.addPrivateKey(privateKey)
	entry := &Entry{
		Alias:            alias,
		PrivateKey:       s.privateKeyByID(privateKey.ID),
		PrivateKeyStatus: PrivateKeyStatusAvailable,
		Chain:            s.canonicalCertificates(certificates),
	}
	s.Entries = append(s.Entries, entry)
	return nil
}

// AddTrustedCertificate 使用指定 alias 添加信任证书条目。
func (s *Store) AddTrustedCertificate(alias string, cert *smx509.Certificate) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return errx.Wrap(ErrInvalidData, "alias must not be empty")
	}
	if s.entryByAlias(alias) != nil {
		return errx.Wrapf(ErrAliasConflict, "alias %q", alias)
	}
	item, err := NewCertificate(cert)
	if err != nil {
		return err
	}
	s.addCertificate(item)
	s.Entries = append(s.Entries, &Entry{Alias: alias, Chain: []*Certificate{s.certificateByID(item.ID)}, Trusted: true})
	return nil
}

// AddEntry 添加已经规范化的密钥库条目。
func (s *Store) AddEntry(entry *Entry) error {
	if entry == nil {
		return errx.Wrap(ErrInvalidData, "entry is nil")
	}
	if strings.TrimSpace(entry.Alias) == "" {
		return errx.Wrap(ErrInvalidData, "alias must not be empty")
	}
	if s.entryByAlias(entry.Alias) != nil {
		return errx.Wrapf(ErrAliasConflict, "alias %q", entry.Alias)
	}
	if entry.PrivateKey != nil && len(entry.Chain) > 0 && !publicKeysEqual(entry.PrivateKey.Signer.Public(), entry.Chain[0].Certificate.PublicKey) {
		return ErrKeyMismatch
	}
	for _, cert := range entry.Chain {
		s.addCertificate(cert)
	}
	if entry.PrivateKey != nil {
		s.addPrivateKey(entry.PrivateKey)
		entry.PrivateKey = s.privateKeyByID(entry.PrivateKey.ID)
	}
	entry.Chain = s.canonicalCertificates(entry.Chain)
	s.Entries = append(s.Entries, entry)
	return nil
}

// RemoveCertificate 按稳定标识移除证书及条目中的引用。
func (s *Store) RemoveCertificate(id string) error {
	for i, cert := range s.Certificates {
		if cert.ID != id {
			continue
		}
		s.Certificates = append(s.Certificates[:i], s.Certificates[i+1:]...)
		for _, entry := range s.Entries {
			filtered := entry.Chain[:0]
			for _, chainCert := range entry.Chain {
				if chainCert.ID != id {
					filtered = append(filtered, chainCert)
				}
			}
			entry.Chain = filtered
		}
		return nil
	}
	return ErrNoCertificate
}

// RemovePrivateKey 按稳定标识移除私钥并保留不可用状态。
func (s *Store) RemovePrivateKey(id string) error {
	for i, key := range s.PrivateKeys {
		if key.ID != id {
			continue
		}
		s.PrivateKeys = append(s.PrivateKeys[:i], s.PrivateKeys[i+1:]...)
		for _, entry := range s.Entries {
			if entry.PrivateKey != nil && entry.PrivateKey.ID == id {
				entry.PrivateKey = nil
				entry.PrivateKeyStatus = PrivateKeyStatusUnavailable
			}
		}
		return nil
	}
	return ErrNoPrivateKey
}

// RemoveEntry 按不区分大小写的 alias 移除条目。
func (s *Store) RemoveEntry(alias string) error {
	for i, entry := range s.Entries {
		if strings.EqualFold(entry.Alias, alias) {
			s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
			return nil
		}
	}
	return errx.Wrapf(ErrInvalidData, "alias %q not found", alias)
}

func (s *Store) addCertificate(cert *Certificate) {
	if s.certificateByID(cert.ID) == nil {
		s.Certificates = append(s.Certificates, cert)
	}
}

func (s *Store) addPrivateKey(key *PrivateKey) {
	if s.privateKeyByID(key.ID) == nil {
		s.PrivateKeys = append(s.PrivateKeys, key)
	}
}

func (s *Store) certificateByID(id string) *Certificate {
	for _, cert := range s.Certificates {
		if cert.ID == id {
			return cert
		}
	}
	return nil
}

func (s *Store) privateKeyByID(id string) *PrivateKey {
	for _, key := range s.PrivateKeys {
		if key.ID == id {
			return key
		}
	}
	return nil
}

func (s *Store) entryByAlias(alias string) *Entry {
	for _, entry := range s.Entries {
		if strings.EqualFold(entry.Alias, alias) {
			return entry
		}
	}
	return nil
}

func (s *Store) canonicalCertificates(items []*Certificate) []*Certificate {
	result := make([]*Certificate, 0, len(items))
	for _, item := range items {
		result = append(result, s.certificateByID(item.ID))
	}
	return result
}

func certificateRole(cert *smx509.Certificate) CertificateRole {
	if cert.IsCA && len(cert.RawSubject) > 0 && len(cert.RawIssuer) > 0 && subtle.ConstantTimeCompare(cert.RawSubject, cert.RawIssuer) == 1 && cert.CheckSignatureFrom(cert) == nil {
		return CertificateRoleRoot
	}
	if cert.IsCA {
		return CertificateRoleIntermediate
	}
	return CertificateRoleLeaf
}

func keyAlgorithm(key crypto.Signer) KeyAlgorithm {
	if sm2.IsSM2PublicKey(key.Public()) {
		return KeyAlgorithmSM2
	}
	switch key.(type) {
	case *rsa.PrivateKey:
		return KeyAlgorithmRSA
	case *ecdsa.PrivateKey:
		return KeyAlgorithmEC
	default:
		return KeyAlgorithmUnknown
	}
}

func publicKeysEqual(left, right any) bool {
	leftDER, leftErr := smx509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := smx509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && subtle.ConstantTimeCompare(leftDER, rightDER) == 1
}
