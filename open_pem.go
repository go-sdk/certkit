package certkit

import (
	"bytes"
	"crypto"
	"encoding/pem"
	"fmt"

	"github.com/emmansun/gmsm/pkcs8"
	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

func openPEM(data []byte, options OpenOptions) (*Store, error) {
	store := NewStore()
	store.Source = SourceInfo{Format: FormatPEM, Encoding: EncodingPEM, IntegrityVerified: true}
	rest := data
	index := 0
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				store.Diagnostics = append(store.Diagnostics, Diagnostic{Level: DiagnosticWarning, Code: "pem_trailing_data", Message: "pem input contains unparsed data"})
			}
			break
		}
		rest = remaining
		switch block.Type {
		case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
			certs, err := smx509.ParseCertificates(block.Bytes)
			if err != nil {
				return nil, errx.Wrap(err, "parse pem certificate")
			}
			for _, cert := range certs {
				item, itemErr := NewCertificate(cert)
				if itemErr != nil {
					return nil, itemErr
				}
				item.Source = SourceRef{Format: FormatPEM, Index: index}
				store.addCertificate(item)
			}
		case "PKCS7", "PKCS #7 SIGNED DATA", "CMS":
			child, err := openPKCS7(block.Bytes, options)
			if err != nil {
				return nil, err
			}
			mergeStoreObjects(store, child)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "SM2 PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			der := block.Bytes
			password, passwordErr := passwordFor(options, PasswordRequest{Format: FormatPEM, Purpose: PasswordPurposePrivateKey})
			// 读取端需要兼容仍在使用的 RFC 1423 加密 PEM。
			//nolint:staticcheck
			//goland:noinspection GoDeprecation
			if smx509.IsEncryptedPEMBlock(block) {
				if passwordErr != nil {
					return store, passwordErr
				}
				// 读取端需要兼容仍在使用的 RFC 1423 加密 PEM。
				//nolint:staticcheck
				//goland:noinspection GoDeprecation
				der, passwordErr = smx509.DecryptPEMBlock(block, password)
				if passwordErr != nil {
					return store, errx.Wrap(ErrPassword, "decrypt pem private key")
				}
			}
			if block.Type == "ENCRYPTED PRIVATE KEY" && passwordErr != nil {
				return store, passwordErr
			}
			key, keyErr := parsePrivateKey(der, password)
			if keyErr != nil {
				if block.Type == "ENCRYPTED PRIVATE KEY" {
					return store, errx.Wrap(ErrPassword, "decrypt pkcs8 private key")
				}
				return store, keyErr
			}
			item, itemErr := NewPrivateKey(key)
			if itemErr != nil {
				return nil, itemErr
			}
			item.Source = SourceRef{Format: FormatPEM, Index: index}
			store.addPrivateKey(item)
		default:
			store.Diagnostics = append(store.Diagnostics, Diagnostic{Level: DiagnosticInfo, Code: "pem_block_ignored", Message: fmt.Sprintf("pem block %q was not imported", block.Type)})
		}
		index++
	}
	if len(store.Certificates) == 0 && len(store.PrivateKeys) == 0 {
		return nil, errx.Wrap(ErrInvalidData, "pem contains no supported certificate or private key")
	}
	return store, nil
}

func parsePrivateKey(der, password []byte) (crypto.Signer, error) {
	parsers := []func([]byte) (any, error){
		func(data []byte) (any, error) { return smx509.ParsePKCS8PrivateKey(data) },
		func(data []byte) (any, error) { return smx509.ParsePKCS1PrivateKey(data) },
		func(data []byte) (any, error) { return smx509.ParseECPrivateKey(data) },
		func(data []byte) (any, error) { return smx509.ParseSM2PrivateKey(data) },
	}
	if len(password) > 0 {
		parsers = append([]func([]byte) (any, error){func(data []byte) (any, error) { return pkcs8.ParsePKCS8PrivateKey(data, password) }}, parsers...)
	}
	for _, parse := range parsers {
		key, err := parse(der)
		if err != nil {
			continue
		}
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	return nil, errx.Wrap(ErrInvalidData, "unsupported private key")
}

func unwrapPEM(data []byte) []byte {
	if block, _ := pem.Decode(data); block != nil {
		return block.Bytes
	}
	return data
}
