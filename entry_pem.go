package certkit

import "github.com/go-sdk/core/errx"

// CertificateChainPEM 按叶子证书、中间 CA 到根 CA 的顺序输出 PEM 证书链。
// EncodeOptions.ExcludeRootCertificates 用于控制是否剔除自签根证书。
func (e *Entry) CertificateChainPEM(options EncodeOptions) ([]byte, error) {
	if e == nil {
		return nil, ErrNoCertificate
	}
	store := NewStore()
	written := 0
	for _, item := range e.Chain {
		if item == nil || item.Certificate == nil || len(item.Certificate.Raw) == 0 {
			return nil, errx.Wrap(ErrInvalidData, "certificate chain contains an empty certificate")
		}
		if options.ExcludeRootCertificates && certificateRole(item.Certificate) == CertificateRoleRoot {
			continue
		}
		store.addCertificate(item)
		written++
	}
	if written == 0 {
		return nil, ErrNoCertificate
	}
	data, _, err := store.Encode(FormatPEM, options)
	return data, err
}

// PrivateKeyPEM 将当前条目的可用私钥输出为 PKCS#8 PEM。
// EncodeOptions.EncryptPEMPrivateKey 和 Password 用于控制私钥加密。
func (e *Entry) PrivateKeyPEM(options EncodeOptions) ([]byte, error) {
	if e == nil || e.PrivateKey == nil || e.PrivateKey.Signer == nil || e.PrivateKeyStatus != PrivateKeyStatusAvailable {
		return nil, ErrNoPrivateKey
	}
	store := NewStore()
	store.addPrivateKey(e.PrivateKey)
	data, _, err := store.Encode(FormatPEM, options)
	return data, err
}
