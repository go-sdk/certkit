package certkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"net"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
)

// KeyOptions 配置 RSA、ECDSA 或 SM2 私钥生成参数。
type KeyOptions struct {
	Algorithm KeyAlgorithm
	RSABits   int
	Curve     string
}

// GeneratePrivateKey 生成配置指定的 RSA、ECDSA 或 SM2 私钥。
func GeneratePrivateKey(options KeyOptions) (crypto.Signer, error) {
	switch options.Algorithm {
	case "", KeyAlgorithmRSA:
		bits := options.RSABits
		if bits == 0 {
			bits = 3072
		}
		if bits < 2048 {
			return nil, errx.Wrap(ErrInvalidData, "rsa key size must be at least 2048 bits")
		}
		return rsa.GenerateKey(rand.Reader, bits)
	case KeyAlgorithmEC:
		var curve elliptic.Curve
		switch strings.ToUpper(options.Curve) {
		case "", "P-256", "P256":
			curve = elliptic.P256()
		case "P-384", "P384":
			curve = elliptic.P384()
		case "P-521", "P521":
			curve = elliptic.P521()
		default:
			return nil, errx.Wrapf(ErrInvalidData, "unsupported ec curve %q", options.Curve)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case KeyAlgorithmSM2:
		return sm2.GenerateKey(rand.Reader)
	default:
		return nil, errx.Wrapf(ErrUnsupportedAlgorithm, "key algorithm %q", options.Algorithm)
	}
}

// CreateRootCA 创建自签根 CA 证书及其私钥。

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, errx.Wrap(err, "generate certificate serial number")
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func subjectKeyID(publicKey any) ([]byte, error) {
	der, err := smx509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, errx.Wrap(err, "marshal subject public key")
	}
	sum := sha256.Sum256(der)
	return append([]byte(nil), sum[:20]...), nil
}

func cloneIPs(values []net.IP) []net.IP {
	result := make([]net.IP, 0, len(values))
	for _, value := range values {
		result = append(result, append(net.IP(nil), value...))
	}
	return result
}

func defaultKeyUsage(publicKey any, isCA bool) smx509.KeyUsage {
	if isCA {
		return smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign | smx509.KeyUsageDigitalSignature
	}
	if _, ok := publicKey.(*rsa.PublicKey); ok {
		return smx509.KeyUsageDigitalSignature | smx509.KeyUsageKeyEncipherment
	}
	return smx509.KeyUsageDigitalSignature
}
