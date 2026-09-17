package certkit

import "github.com/go-sdk/core/errx"

var (
	// ErrPassword 表示缺少密码或密码无法解密输入。
	ErrPassword = errx.New("password required or incorrect")
	// ErrUnsupportedFormat 表示已识别但未实现解析或输出的格式。
	ErrUnsupportedFormat = errx.New("unsupported certificate format")
	// ErrUnknownFormat 表示无法从内容判断输入格式。
	ErrUnknownFormat = errx.New("unknown certificate format")
	// ErrInvalidData 表示输入结构、边界或证书语义无效。
	ErrInvalidData = errx.New("invalid certificate data")
	// ErrKeyMismatch 表示私钥与证书公钥不匹配。
	ErrKeyMismatch = errx.New("private key does not match certificate")
	// ErrAliasConflict 表示密钥库 alias 重复。
	ErrAliasConflict = errx.New("alias already exists")
	// ErrLossyConversion 表示转换会丢弃证书或私钥。
	ErrLossyConversion = errx.New("conversion would discard data")
	// ErrNoCertificate 表示操作需要证书但 Store 中不存在可用证书。
	ErrNoCertificate = errx.New("certificate not found")
	// ErrNoPrivateKey 表示操作需要私钥但 Store 中不存在可用私钥。
	ErrNoPrivateKey = errx.New("private key not found")
	// ErrUnsupportedAlgorithm 表示请求的密码算法不受支持。
	ErrUnsupportedAlgorithm = errx.New("unsupported cryptographic algorithm")
)
