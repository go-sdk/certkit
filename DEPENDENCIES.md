# 第三方依赖选型

本文记录证书格式和验证相关依赖的选型边界，便于升级时重新核对安全修复和兼容性。
直接依赖的实际版本以 `go.mod` 为准；`internal/*/UPSTREAM.md` 中的版本记录本地源码基线和补丁来源，不随直接依赖升级自动变更。

## TLCP

TLCP 1.1 使用 `gitee.com/Trisia/gotlcp` v1.6.2。该实现基于
`github.com/emmansun/gmsm` 的 `smx509`，可直接复用 certkit 的 SM2 证书模型，
并支持在 ClientHello 中携带 SNI、服务端双证书、握手上下文取消及 SM4-GCM/CBC
密码套件。

certkit 仅使用其客户端握手和连接状态，不依赖内部协议结构。握手阶段跳过依赖库的
证书信任验证以收集服务端证书，之后由 certkit 分别验证签名证书和加密证书的主机名、
信任链及服务端链完整性。升级时应重新核对 SNI 编码、双证书顺序、证书链顺序、
`HandshakeContext` 取消行为和 `ConnectionState` 字段语义。

## PKCS12

标准 RSA 和 ECDSA PKCS12 使用 `software.sslmate.com/src/go-pkcs12` v0.7.4。该版本包含现代算法配置、PBMAC1 显式密钥长度校验，以及 PBES2 中 PBKDF2 PRF 的显式 ASN.1 `NULL` 参数编码，避免省略参数导致严格解析器拒绝输出。

标准输出通过 certkit 的 `PKCS12Profile` 映射到上游固定的 `Modern2023`、`Modern2026`、`LegacyRC2` 和 `LegacyDES`。
默认及现有 `modern` 仍为 `Modern2026`，现有 `legacy` 仍为 `LegacyDES`，不依赖上游可变化的 `Modern`、`Legacy` 别名。
派生次数覆盖使用上游 `WithIterations` 创建编码器副本；标准和国密输出均不修改共享编码器。
对外配置及兼容边界集中维护在 [README.md](README.md#pkcs12-算法配置)。

`github.com/emmansun/go-pkcs12` v0.4.2 增加了 SM2、SM3 和 SM4，但与 SSLMate v0.7.3 对比后确认缺少以下输入校验：

- PBMAC1 显式 key length 必须在 20 到 64 字节之间；
- PBES2 的 IV 长度必须等于所选分组密码的 block size。

因此国密 PKCS12 使用位于 `internal/pkcs12` 的固定版本。本地版本以 emmansun v0.4.2 为基础，补入上述校验及 PBES2 中 PBKDF2 PRF 的显式 ASN.1 `NULL` 参数编码；标准 PKCS12 不经过该 fork。补丁来源见 [internal/pkcs12/UPSTREAM.md](internal/pkcs12/UPSTREAM.md)。升级任一上游时，应重新比较 `mac.go`、`crypto.go` 和密码校验相关测试。

## PKCS7

`github.com/mozilla-services/pkcs7` v0.10.0 使用标准库 `crypto/x509`，不支持 SM2 证书。`github.com/emmansun/gmsm/pkcs7` v0.45.0 以同一实现谱系为基础，改用 `smx509` 并补充 SM2 等算法，所以解析和输出选择
gmsm。

两者的 PKCS7 入口都会先把 BER 转为 DER。gmsm v0.45.0 已补充高位标签和长度字段的部分越界检查，但上游转换器仍未完整拒绝尾随数据，也未限制 ASN.1 嵌套深度。`internal/ber` 因此在调用 gmsm 前执行以下限制：

- 输入必须只包含一个完整 ASN.1 对象，拒绝尾随数据；
- 长度字段和父子对象边界必须在输入范围内；
- 不定长编码必须正确终止；
- ASN.1 嵌套深度最多 128 层。

该层只负责 BER 边界校验和 DER 规范化，PKCS7/CMS 的 OID、证书和算法语义仍由 gmsm 处理。

`internal/ber` 基于 Mozilla PKCS7 v0.10.0 的 `ber.go`，具体本地修改和升级检查范围见 `internal/ber/UPSTREAM.md`。

## OCSP

标准库和 `golang.org/x/crypto/ocsp` 使用 `crypto/x509`，不能验证 SM2 签名证书。`internal/ocsp` 基于 `golang.org/x/crypto/ocsp` v0.57.0，改用
`smx509` 并补充 SM2WithSM3、RSA-PSS、Responder 证书授权、响应时间和请求证书匹配校验。

本地实现只保留 certkit 创建 OCSP 请求和解析响应所需的内部 API，不作为独立公共 OCSP 包。具体差异和升级检查范围见 `internal/ocsp/UPSTREAM.md`。
