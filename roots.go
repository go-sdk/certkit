package certkit

import (
	"crypto/x509"

	"github.com/emmansun/gmsm/smx509"
	"github.com/go-sdk/core/errx"
	"golang.org/x/crypto/x509roots/fallback/bundle"
)

// TrustStore 保存一个或多个互相独立的根证书池及其约束。
type TrustStore struct {
	pools []*smx509.CertPool
}

// SystemRoots 返回当前系统信任根。
func SystemRoots() (*TrustStore, error) {
	pool, err := smx509.SystemCertPool()
	if err != nil {
		return nil, errx.Wrap(err, "load system roots")
	}
	return &TrustStore{pools: []*smx509.CertPool{pool}}, nil
}

// MozillaRoots 返回内嵌的 Mozilla 信任根及其约束。
func MozillaRoots() (*TrustStore, error) {
	pool := smx509.NewCertPool()
	for root := range bundle.Roots() {
		cert, err := smx509.ParseCertificate(root.Certificate)
		if err != nil {
			return nil, errx.Wrap(err, "parse Mozilla root")
		}
		if root.Constraint == nil {
			pool.AddCert(cert)
			continue
		}
		constraint := root.Constraint
		pool.AddCertWithConstraint(cert, func(chain []*smx509.Certificate) error {
			standardChain := make([]*x509.Certificate, 0, len(chain))
			for _, chainCert := range chain {
				standardCert, parseErr := x509.ParseCertificate(chainCert.Raw)
				if parseErr != nil {
					return parseErr
				}
				standardChain = append(standardChain, standardCert)
			}
			return constraint(standardChain)
		})
	}
	return &TrustStore{pools: []*smx509.CertPool{pool}}, nil
}

// SystemAndMozillaRoots 返回同时包含系统和 Mozilla 根的独立信任库。
func SystemAndMozillaRoots() (*TrustStore, error) {
	system, err := SystemRoots()
	if err != nil {
		return nil, err
	}
	mozilla, err := MozillaRoots()
	if err != nil {
		return nil, err
	}
	return &TrustStore{pools: append(system.pools, mozilla.pools...)}, nil
}

// CustomRoots 使用给定证书创建独立信任库。
func CustomRoots(certs ...*smx509.Certificate) *TrustStore {
	pool := smx509.NewCertPool()
	for _, cert := range certs {
		if cert != nil {
			pool.AddCert(cert)
		}
	}
	return &TrustStore{pools: []*smx509.CertPool{pool}}
}

// Add 将证书加入自定义信任库的首个证书池。
func (t *TrustStore) Add(cert *smx509.Certificate) {
	if cert == nil {
		return
	}
	if len(t.pools) == 0 {
		t.pools = append(t.pools, smx509.NewCertPool())
	}
	t.pools[0].AddCert(cert)
}

func (t *TrustStore) verify(cert *smx509.Certificate, options smx509.VerifyOptions) ([][]*smx509.Certificate, error) {
	if t == nil || len(t.pools) == 0 {
		return cert.Verify(options)
	}
	var result error
	for _, pool := range t.pools {
		options.Roots = pool
		chains, err := cert.Verify(options)
		if err == nil {
			return chains, nil
		}
		result = errx.Join(result, err)
	}
	return nil, result
}
