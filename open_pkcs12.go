package certkit

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
	sslmatepkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/go-sdk/certkit/internal/pkcs12"
)

func openPKCS12(data []byte, options OpenOptions) (*Store, error) {
	password, err := passwordFor(options, PasswordRequest{Format: FormatPKCS12, Purpose: PasswordPurposeContainer})
	if err != nil {
		return nil, err
	}
	if !looksLikeShangMiPKCS12(data) {
		return openStandardPKCS12(data, password)
	}
	// ToPEM 是当前保留多 bag alias 和 localKeyID 的唯一上游接口，返回的原始私钥会按实际 DER 类型解析。
	//nolint:staticcheck
	//goland:noinspection GoDeprecation
	if blocks, blockErr := pkcs12.ToPEM(data, string(password)); blockErr == nil {
		return storeFromPKCS12Blocks(blocks)
	}
	key, leaf, chain, decodeErr := pkcs12.DecodeChain(data, string(password))
	if decodeErr != nil {
		certs, trustErr := pkcs12.DecodeTrustStore(data, string(password))
		if trustErr != nil {
			return nil, errx.Wrap(ErrPassword, "open pkcs12")
		}
		store := NewStore()
		store.Source = SourceInfo{Format: FormatPKCS12, Encoding: EncodingDER, IntegrityVerified: true}
		for i, cert := range certs {
			item, _ := NewCertificate(cert)
			item.Source = SourceRef{Format: FormatPKCS12, Index: i}
			store.addCertificate(item)
			store.Entries = append(store.Entries, &Entry{Alias: fmt.Sprintf("certificate-%d", i+1), Chain: []*Certificate{item}, Trusted: true})
		}
		return store, nil
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errx.Wrap(ErrInvalidData, "pkcs12 private key does not implement crypto.Signer")
	}
	store := NewStore()
	store.Source = SourceInfo{Format: FormatPKCS12, Encoding: EncodingDER, IntegrityVerified: true}
	certificates := append([]*smx509.Certificate{leaf}, chain...)
	if err := store.AddKeyPair(defaultAlias(leaf), signer, certificates...); err != nil {
		return nil, err
	}
	for i, cert := range store.Certificates {
		cert.Source = SourceRef{Format: FormatPKCS12, Alias: store.Entries[0].Alias, Index: i}
	}
	store.PrivateKeys[0].Source = SourceRef{Format: FormatPKCS12, Alias: store.Entries[0].Alias}
	return store, nil
}

func openStandardPKCS12(data, password []byte) (*Store, error) {
	// ToPEM 是当前保留多 bag alias 和 localKeyID 的唯一上游接口，返回的原始私钥会按实际 DER 类型解析。
	//nolint:staticcheck
	//goland:noinspection GoDeprecation
	if blocks, err := sslmatepkcs12.ToPEM(data, string(password)); err == nil {
		return storeFromPKCS12Blocks(blocks)
	}
	key, leaf, chain, decodeErr := sslmatepkcs12.DecodeChain(data, string(password))
	if decodeErr != nil {
		certs, trustErr := sslmatepkcs12.DecodeTrustStore(data, string(password))
		if trustErr != nil {
			return nil, errx.Wrap(ErrPassword, "open pkcs12")
		}
		store := NewStore()
		store.Source = SourceInfo{Format: FormatPKCS12, Encoding: EncodingDER, IntegrityVerified: true}
		for i, standardCert := range certs {
			cert, err := smx509.ParseCertificate(standardCert.Raw)
			if err != nil {
				return nil, errx.Wrap(err, "parse pkcs12 certificate")
			}
			item, _ := NewCertificate(cert)
			item.Source = SourceRef{Format: FormatPKCS12, Index: i}
			store.addCertificate(item)
			store.Entries = append(store.Entries, &Entry{Alias: fmt.Sprintf("certificate-%d", i+1), Chain: []*Certificate{item}, Trusted: true})
		}
		return store, nil
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errx.Wrap(ErrInvalidData, "pkcs12 private key does not implement crypto.Signer")
	}
	certificates := make([]*smx509.Certificate, 0, len(chain)+1)
	for _, standardCert := range append([]*x509.Certificate{leaf}, chain...) {
		cert, parseErr := smx509.ParseCertificate(standardCert.Raw)
		if parseErr != nil {
			return nil, errx.Wrap(parseErr, "parse pkcs12 certificate")
		}
		certificates = append(certificates, cert)
	}
	store := NewStore()
	store.Source = SourceInfo{Format: FormatPKCS12, Encoding: EncodingDER, IntegrityVerified: true}
	if err := store.AddKeyPair(defaultAlias(certificates[0]), signer, certificates...); err != nil {
		return nil, err
	}
	return store, nil
}

func storeFromPKCS12Blocks(blocks []*pem.Block) (*Store, error) {
	store := NewStore()
	store.Source = SourceInfo{Format: FormatPKCS12, Encoding: EncodingDER, IntegrityVerified: true}
	type keyAlias struct {
		key   *PrivateKey
		alias string
	}
	keys := make([]keyAlias, 0)
	certificateAliases := map[string]string{}
	for i, block := range blocks {
		alias := strings.TrimSpace(block.Headers["friendlyName"])
		switch block.Type {
		case "CERTIFICATE":
			cert, err := smx509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errx.Wrap(err, "parse pkcs12 certificate bag")
			}
			item, _ := NewCertificate(cert)
			item.Source = SourceRef{Format: FormatPKCS12, Alias: alias, Index: i}
			store.addCertificate(item)
			if alias != "" {
				certificateAliases[item.ID] = alias
			}
		case "PRIVATE KEY":
			key, err := parsePrivateKey(block.Bytes, nil)
			if err != nil {
				return nil, errx.Wrap(err, "parse pkcs12 private key bag")
			}
			item, _ := NewPrivateKey(key)
			item.Source = SourceRef{Format: FormatPKCS12, Alias: alias, Index: i}
			store.addPrivateKey(item)
			keys = append(keys, keyAlias{key: item, alias: alias})
		}
	}
	for _, value := range keys {
		alias := value.alias
		if alias == "" {
			alias = "key-" + value.key.ID[:12]
		}
		entry := &Entry{Alias: uniqueEntryAlias(store, alias), PrivateKey: store.privateKeyByID(value.key.ID), PrivateKeyStatus: PrivateKeyStatusAvailable}
		for _, cert := range store.Certificates {
			if publicKeysEqual(value.key.Signer.Public(), cert.Certificate.PublicKey) {
				entry.Chain = buildCertificateChain(cert, store.Certificates)
				break
			}
		}
		store.Entries = append(store.Entries, entry)
	}
	if len(keys) == 0 {
		for _, cert := range store.Certificates {
			alias := certificateAliases[cert.ID]
			if alias == "" {
				alias = defaultAlias(cert.Certificate)
			}
			store.Entries = append(store.Entries, &Entry{Alias: uniqueEntryAlias(store, alias), Chain: []*Certificate{cert}, Trusted: true})
		}
	}
	if len(store.Certificates) == 0 && len(store.PrivateKeys) == 0 {
		return nil, errx.Wrap(ErrInvalidData, "pkcs12 contains no supported certificate or private key")
	}
	return store, nil
}

func uniqueEntryAlias(store *Store, alias string) string {
	if store.entryByAlias(alias) == nil {
		return alias
	}
	for index := 2; ; index++ {
		candidate := fmt.Sprintf("%s-%d", alias, index)
		if store.entryByAlias(candidate) == nil {
			return candidate
		}
	}
}

func looksLikeShangMiPKCS12(data []byte) bool {
	oids := []asn1.ObjectIdentifier{
		{1, 2, 156, 10197, 1, 104, 2},
		{1, 2, 156, 10197, 1, 401},
		{1, 2, 156, 10197, 1, 401, 2},
		{1, 2, 156, 10197, 1, 301},
		{1, 2, 156, 10197, 1, 501},
	}
	for _, oid := range oids {
		encoded, _ := asn1.Marshal(oid)
		if bytes.Contains(data, encoded) {
			return true
		}
	}
	return false
}
