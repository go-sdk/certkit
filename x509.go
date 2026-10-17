package certkit

import "github.com/emmansun/gmsm/smx509"

// X509Certificate 是支持 RSA、ECDSA 和 SM2 的底层证书类型，与保存来源元数据的 Certificate 区分。
// 别名保持 smx509 的类型身份，已有调用方无需转换。
type X509Certificate = smx509.Certificate

// KeyUsage 表示证书允许的密钥用途，可通过位或组合 KeyUsage 常量。
type KeyUsage = smx509.KeyUsage

// KeyUsage 常量沿用底层 X.509 实现的用途及位值。
const (
	KeyUsageDigitalSignature  = smx509.KeyUsageDigitalSignature
	KeyUsageContentCommitment = smx509.KeyUsageContentCommitment
	KeyUsageKeyEncipherment   = smx509.KeyUsageKeyEncipherment
	KeyUsageDataEncipherment  = smx509.KeyUsageDataEncipherment
	KeyUsageKeyAgreement      = smx509.KeyUsageKeyAgreement
	KeyUsageCertSign          = smx509.KeyUsageCertSign
	KeyUsageCRLSign           = smx509.KeyUsageCRLSign
	KeyUsageEncipherOnly      = smx509.KeyUsageEncipherOnly
	KeyUsageDecipherOnly      = smx509.KeyUsageDecipherOnly
)

// ExtKeyUsage 表示证书允许的扩展用途，各用途通过切片独立声明，不按位组合。
type ExtKeyUsage = smx509.ExtKeyUsage

// ExtKeyUsage 常量沿用底层 X.509 实现的扩展用途及编号。
const (
	ExtKeyUsageAny                            = smx509.ExtKeyUsageAny
	ExtKeyUsageServerAuth                     = smx509.ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth                     = smx509.ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning                    = smx509.ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection                = smx509.ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem                 = smx509.ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel                    = smx509.ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser                      = smx509.ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping                   = smx509.ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning                    = smx509.ExtKeyUsageOCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto     = smx509.ExtKeyUsageMicrosoftServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCrypto      = smx509.ExtKeyUsageNetscapeServerGatedCrypto
	ExtKeyUsageMicrosoftCommercialCodeSigning = smx509.ExtKeyUsageMicrosoftCommercialCodeSigning
	ExtKeyUsageMicrosoftKernelCodeSigning     = smx509.ExtKeyUsageMicrosoftKernelCodeSigning
)
