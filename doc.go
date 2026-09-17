// Package certkit 统一提供 X.509 证书、私钥和密钥库的解析、转换、签发、
// 吊销验证、信任根管理及 TLS 服务探测能力。
//
// Open 根据文件内容识别 PEM、DER、PKCS7、PKCS12 和 JKS，不依赖文件扩展名。
// Store 保存规范化后的证书、私钥及密钥库条目关系，并可继续增加对象或合并其他文件：
//
//	store, err := certkit.Open(data, certkit.OpenOptions{Password: password})
//	if err != nil && !errx.Is(err, certkit.ErrPassword) {
//		return err
//	}
//	err = store.AddKeyPair("server", key, leaf, intermediate)
//
// 密码错误时，Open 会尽量返回已经安全解析的证书数据，并同时返回 ErrPassword。
// 调用方应使用 errx.Is 判断该错误；结构损坏和不支持格式使用各自的哨兵错误。
// JCEKS 和 BKS 只进行格式识别，不提供解析和输出。
//
// Store.Encode 输出 PEM、DER、PKCS7、PKCS12 或 JKS。PKCS12 和 JKS 不设置默认
// 输出密码，调用方必须通过 EncodeOptions 显式传入。可能丢弃证书或私钥的转换默认
// 返回 ErrLossyConversion，只有明确设置 AllowLossy 后才会执行。
//
// CreateRootCA、IssueCertificate、CreateCertificateRequest 和
// SignCertificateRequest 支持 RSA、ECDSA 和 SM2，可构造根 CA、中间 CA、终端证书
// 及 PKCS#10 CSR。CreateCRL、CheckCRL 和 CheckOCSP 提供本地吊销数据处理；仅
// FetchAndCheckCRL 与 FetchAndCheckOCSP 会主动访问证书扩展中的网络地址。
//
// SystemRoots、MozillaRoots、SystemAndMozillaRoots 和 CustomRoots 构造独立信任库。
// MozillaRoots 使用内嵌的 Mozilla 根集合及其约束，不修改进程级根证书配置。
//
// InspectTLS 按指定版本分别建立 TLS 连接，支持 TLS 1.0、1.1、1.2 和 1.3，报告
// SNI、协商参数、服务端证书、主机名、信任链、链完整性及 stapled OCSP。TLS 国密
// 协议不在当前支持范围内。
//
// 安装：
//
//	go get github.com/go-sdk/certkit
package certkit
