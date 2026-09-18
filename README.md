# certkit

`certkit` 是统一的 X.509 证书工具包。公共能力集中在根包，支持证书、私钥、证书链和密钥库的解析、合并、转换、签发、吊销检查以及 TLS 服务探测。

## 环境要求

- Go 1.27 或更高版本

## 安装

```bash
go get github.com/go-sdk/certkit
```

## 格式与算法

| 能力     | 支持范围                                                 |
|----------|----------------------------------------------------------|
| 公钥算法 | RSA、ECDSA、SM2                                          |
| 输入格式 | PEM、DER、PKCS7/CMS 证书集合、PKCS12/PFX、JKS            |
| 输出格式 | PEM、DER、PKCS7、PKCS12/PFX、JKS                         |
| CA       | 自签根 CA、中间 CA、终端证书、PKCS#10 CSR 签发、CRL 生成 |
| 吊销检查 | CRL、OCSP、TLS stapled OCSP，包括 SM2 签名验证           |
| TLS 探测 | TLS 1.0、1.1、1.2、1.3 独立握手和证书链验证              |

JCEKS 和 BKS 只进行格式识别，解析和输出返回 `ErrUnsupportedFormat`。TLS 国密协议暂不支持；SM2 证书本身仍可解析、签发和执行 CRL/OCSP 验证。

## 打开和合并文件

`Open` 根据内容识别格式，不依赖文件扩展名：

```go
store, err := certkit.Open(data, certkit.OpenOptions{
	Password: password,
})
if err != nil && !errx.Is(err, certkit.ErrPassword) {
	return err
}
```

`Store` 同时保存规范化后的证书、私钥以及原密钥库的条目关系：

```go
type Store struct {
	Source       SourceInfo
	Entries      []*Entry
	Certificates []*Certificate
	PrivateKeys  []*PrivateKey
	Diagnostics  []Diagnostic
}
```

可以继续增加对象或合并其他文件：

```go
err = store.AddCertificate(cert)
err = store.AddPrivateKey(key)
err = store.AddKeyPair("server", key, leaf, intermediate)
err = store.AddTrustedCertificate("root", root)
report, err := store.Add(otherData, certkit.OpenOptions{Password: otherPassword})
```

证书和私钥通过公钥 DER 指纹匹配。证书链使用签名、Issuer/Subject 和 AKI/SKI 关系排序。

## JKS 密码和别名

- 显式提供 store password 后，只使用该密码，不回退到其他候选。
- 未提供 store password 时默认尝试 JDK 常用密码 `changeit`；设置 `DisableJKSDefaultPassword` 可以关闭。
- private-key entry 优先使用 `KeyPasswords[alias]`，之后调用 `PasswordProvider`，再尝试已经确认的 store password。
- 密码探测失败但 JKS 条目边界可以安全解析时，返回部分 `Store` 和 `ErrPassword`。证书及 alias 被保留，私钥标记为 `PrivateKeyStatusUnavailable`，`Source.IntegrityVerified` 表示 store 完整性是否已经验证。
- alias 比较不区分大小写，读取时保留原始写法。接受 `X509` 和 `X.509` 两种证书类型。
- 单个未命名的新增条目输出 JKS 时使用 `mykey`；多个条目必须提供唯一 alias。
- JKS 私钥统一以 PKCS#8 DER 写入。

错误可以通过 `core/errx` 判断：

```go
if errx.Is(err, certkit.ErrPassword) {
	// store 可能仍包含可用的证书数据。
}
```

## 格式输出

```go
output, report, err := store.Encode(certkit.FormatPKCS12, certkit.EncodeOptions{
	Password: []byte("explicit-password"),
	Alias:    "server",
})
```

JKS 和 PKCS12 不设置默认输出密码，必须显式提供非空密码。JKS 密码至少六个字节；未单独设置 `KeyPassword` 时使用显式提供的 store password。加密 PEM 同样需要显式密码。

PKCS12 的 RSA/ECDSA 编解码基于 SSLMate 安全修复版本，默认使用 `Modern2026`；国密 PKCS12 使用 emmansun 的 SM2/SM3/SM4 实现。PKCS7 私钥丢失、DER 多对象截断和单条目 PKCS12 选择等有损转换默认返回
`ErrLossyConversion`，只有 `AllowLossy` 为 true 时才允许。

两组上游的差异和本地补丁边界见 [DEPENDENCIES.md](DEPENDENCIES.md)。

## 创建和签发证书

```go
root, err := certkit.CreateRootCA(certkit.RootCAOptions{
	Alias:   "root-ca",
	Subject: pkix.Name{CommonName: "Example Root CA"},
	Key:     certkit.KeyOptions{Algorithm: certkit.KeyAlgorithmRSA, RSABits: 3072},
})

intermediate, err := certkit.IssueCertificate(root, certkit.CertificateOptions{
	Alias:   "intermediate-ca",
	Subject: pkix.Name{CommonName: "Example Intermediate CA"},
	IsCA:    true,
	Key:     certkit.KeyOptions{Algorithm: certkit.KeyAlgorithmEC, Curve: "P-256"},
})

server, err := certkit.IssueCertificate(intermediate, certkit.CertificateOptions{
	Alias:    "server",
	Subject:  pkix.Name{CommonName: "example.com"},
	DNSNames: []string{"example.com"},
	Key:      certkit.KeyOptions{Algorithm: certkit.KeyAlgorithmSM2},
})
```

也可以使用 `CreateCertificateRequest` 创建 CSR，再用 `SignCertificateRequest` 签发外部公钥。

## CRL 和 OCSP

纯验证方法不访问网络：

```go
crlResult, err := certkit.CheckCRL(cert, issuer, crlData, certkit.CRLOptions{})
ocspResult, err := certkit.CheckOCSP(cert, issuer, responseData, certkit.OCSPOptions{})
```

显式网络方法从证书扩展中的第一个地址获取响应，并接受调用方提供的 `context.Context` 和 `http.Client`：

```go
crlResult, err := certkit.FetchAndCheckCRL(ctx, client, cert, issuer, options)
ocspResult, err := certkit.FetchAndCheckOCSP(ctx, client, cert, issuer, options)
```

## 根证书

```go
roots, err := certkit.SystemRoots()
roots, err = certkit.MozillaRoots()
roots, err = certkit.SystemAndMozillaRoots()
roots = certkit.CustomRoots(certificates...)
```

Mozilla 根来自 `golang.org/x/crypto/x509roots/fallback/bundle` 内嵌的 NSS 根集合，并在链验证时保留其额外约束。库不会修改进程级 `x509.SetFallbackRoots`。

## TLS 探测

```go
report, err := certkit.InspectTLS(
	ctx,
	"192.0.2.10:443",
	certkit.TLSOptions{
		ServerName: "example.com",
		Versions: []certkit.TLSVersion{
			certkit.TLS10,
			certkit.TLS11,
			certkit.TLS12,
			certkit.TLS13,
		},
		Roots: roots,
	},
)
```

每个 TLS 版本使用独立连接，并把 `MinVersion` 和 `MaxVersion` 固定为同一版本。握手成功、主机名匹配、信任链验证、服务端发送链完整性、根证书是否被多余发送以及 stapled OCSP 分别报告。根证书无需由服务端发送。

TLS 1.0/1.1 结果表示使用当前 Go 密码套件策略能否完成握手。库不会修改进程级 `GODEBUG` 来重新启用旧密码套件。

## 测试

默认测试使用运行时生成的证书和本地测试服务，不访问外网：

```bash
make test
```

它覆盖 RSA、ECDSA、SM2 CA 签发，交叉签名和多路径建链，PEM、DER、PKCS7、PKCS12、JKS 往返，密码错误的部分结果，CRL、OCSP、过期证书以及 TLS SNI 和不完整链检测。

公网互操作测试默认跳过，需要显式启用：

```bash
CERTKIT_NETWORK_TESTS=1 make test-network
```

测试内容包括：

- 使用 [DigiCert chain demos](https://knowledge.digicert.com/general-information/digicert-trusted-root-authority-certificates)、[Let's Encrypt test certificates](https://letsencrypt.org/2026/04/10/test-sites/)
和 [Amazon Trust Services test URLs](https://www.amazontrust.com/repository/) 验证公网 TLS 链、RSA/ECDSA、过期和吊销状态；
- 从 [Apple PKI](https://www.apple.com/certificateauthority/)、[DigiCert](https://knowledge.digicert.com/general-information/digicert-trusted-root-authority-certificates)
  和 [Microsoft PKI](https://www.microsoft.com/pkiops/docs/repository.htm) 官方仓库下载公开 PEM/DER 根证书及中间证书，验证自动识别、X.509 字段和 CA 属性；
- 将公开 CA 证书编码为 PKCS12 和 JKS truststore 后重新解析；
- 从固定版本 [NuGet](https://learn.microsoft.com/nuget/reference/signed-packages-reference) 包的 `.signature.p7s` 解析真实 PKCS7 代码签名证书；
- 从固定版本 [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) Sigstore bundle 解析 Fulcio DER 代码签名证书；
- 解析 [badssl](https://badssl.com/download/) 公开客户端 PEM/PFX 和固定版本 [`keystore-go`](https://github.com/pavlo-v-chernykh/keystore-go) Java JKS 样本。

公网样本只保存在测试进程内，不写入仓库或日志。失败可能来自本地网络限制、证书轮换、样本迁移或代码回归，需要结合失败来源判断。

GitHub Actions 会在 lint 和默认测试通过后执行该测试；公网互操作步骤允许失败并产生 warning，不阻断工作流。

CRL 网络获取默认最多读取 16 MiB，OCSP 响应默认最多读取 1 MiB；调用方可以通过对应 Options 的 `MaxSize` 收紧或放宽限制。

## 开发约定

修改代码前先阅读 `AGENTS.md`、`PROJECT_MAP.md`、`DEPENDENCIES.md` 和本文件。发现文档与实现不一致时，应在同一次修改中更新。

```bash
make lint          # 整理依赖并执行 golangci-lint
make test          # 使用竞态检测运行本地确定性测试
make test-network  # 访问公开 CA 测试站点执行互操作测试
```

默认测试不得访问外网；`make test-network` 的结果受本地网络、公开 CA 服务状态、证书轮换和外部样本可用性影响。
