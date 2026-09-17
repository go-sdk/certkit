# 第三方依赖选型

本文记录证书格式和验证相关依赖的选型边界，便于升级时重新核对安全修复和兼容性。

## PKCS12

标准 RSA 和 ECDSA PKCS12 使用 `software.sslmate.com/src/go-pkcs12` v0.7.3。该版本包含现代算法配置，并修复了 PBMAC1 过短密钥可能导致错误密码被接受的问题。

`github.com/emmansun/go-pkcs12` v0.4.2 增加了 SM2、SM3 和 SM4，但与 SSLMate v0.7.3 对比后确认缺少以下输入校验：

- PBMAC1 显式 key length 必须在 20 到 64 字节之间；
- PBES2 的 IV 长度必须等于所选分组密码的 block size。

因此国密 PKCS12 使用位于 `internal/pkcs12` 的固定版本。本地版本以 emmansun v0.4.2 为基础，只补入上述校验；标准 PKCS12 不经过该 fork。升级任一上游时，应重新比较 `mac.go`、`crypto.go` 和密码校验相关测试。

## PKCS7

`github.com/mozilla-services/pkcs7` v0.10.0 使用标准库 `crypto/x509`，不支持 SM2 证书。`github.com/emmansun/gmsm/pkcs7` v0.44.1 以同一实现谱系为基础，改用 `smx509` 并补充 SM2 等算法，所以解析和输出选择
gmsm。

两者的 PKCS7 入口都会先把 BER 转为 DER。对比发现，上游转换器没有完整拒绝尾随数据，gmsm 版本还缺少 Mozilla 版本已有的部分长度边界检查。`internal/ber` 因此在调用 gmsm 前执行以下限制：

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
