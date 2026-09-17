# 上游说明

本目录基于 `github.com/emmansun/go-pkcs12` v0.4.2，并保留其 BSD 许可证。

本地 fork 补入 `software.sslmate.com/src/go-pkcs12` v0.7.3 的两项输入校验：

- 拒绝短于 20 字节或长于 64 字节的显式 PBMAC1 key length。
- 拒绝长度与所选分组密码不匹配的 PBES2 IV。

标准 RSA 和 ECDSA PKCS12 直接使用 SSLMate；这个 fork 只用于兼容 SM2、SM3 和 SM4。
