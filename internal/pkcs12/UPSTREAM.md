# 上游说明

本目录基于 `github.com/emmansun/go-pkcs12` v0.4.2，并保留其 BSD 许可证。

本地 fork 补入 `software.sslmate.com/src/go-pkcs12` v0.7.3 的两项输入校验：

- 拒绝短于 20 字节或长于 64 字节的显式 PBMAC1 key length。
- 拒绝长度与所选分组密码不匹配的 PBES2 IV。

PBES2 中 PBKDF2 PRF 的 `AlgorithmIdentifier` 显式编码 ASN.1 `NULL` 参数，采用
SSLMate v0.7.4 的编码修复；HMAC-SM3 的参数编码与 `gmsm/pkcs` v0.45.0 保持一致。

标准 RSA 和 ECDSA PKCS12 直接使用 SSLMate；这个 fork 只用于兼容 SM2、SM3 和 SM4。
