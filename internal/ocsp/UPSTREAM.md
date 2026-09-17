# 上游说明

本目录基于 `golang.org/x/crypto/ocsp` v0.57.0，并保留 Go Authors 的 BSD
许可证。

本地版本使用 `github.com/emmansun/gmsm/smx509` 解析证书和验证签名，增加
SM2WithSM3、RSA-PSS、响应证书授权、响应时间及请求证书匹配校验，只保留
certkit 本地 CRL/OCSP API 所需的请求创建和响应解析能力。

升级 `golang.org/x/crypto` 或 `github.com/emmansun/gmsm` 时，应重新比较上游
`ocsp/ocsp.go`、签名算法映射、Responder 证书验证和 ASN.1 边界处理。
