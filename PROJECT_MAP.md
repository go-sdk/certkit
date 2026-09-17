# 项目地图

## 项目定位

`github.com/go-sdk/certkit` 以单一公共包统一 X.509 证书、私钥、密钥库、CA、吊销状态、信任根和 TLS 探测。调用方不需要直接依赖底层 PKCS7、PKCS12、JKS 或国密实现。

## 目录结构

```text
certkit/
├── .github/workflows/golang.yml     GitHub Actions 检查、测试和 Tag Release
├── AGENTS.md                        仓库协作、安全和测试规范
├── ca.go                            根 CA、中间 CA 和终端证书签发
├── chain.go                         证书链及主机名验证
├── crl.go                           CRL 创建、本地验证和显式网络获取
├── csr.go                           PKCS#10 CSR 创建和签发
├── DEPENDENCIES.md                  PKCS7、PKCS12、OCSP 上游对比和本地补丁边界
├── detect.go                        基于文件结构和 OID 的格式识别
├── encode.go                        统一编码入口和转换报告
├── encode_*.go                      PEM、DER、PKCS7、PKCS12、JKS 输出
├── error.go                         可由 errx.Is 判断的公共哨兵错误
├── format.go                        格式、编码和识别置信度
├── key.go                           RSA、ECDSA 和 SM2 私钥生成
├── model.go                         Store、Entry、Certificate、PrivateKey 模型
├── ocsp.go                          OCSP 本地验证和显式网络获取
├── open.go                          自动解析、Store 合并和对象关联
├── open_*.go                        PEM、DER、PKCS7、PKCS12、JKS 解析
├── password.go                      容器和私钥密码选择
├── roots.go                         系统、Mozilla 和自定义信任根
├── tls.go                           TLS 1.0–1.3 分版本探测
├── *_test.go                        本地确定性单元测试和显式公网互操作测试
├── internal/ber/                    Mozilla PKCS7 BER 转换器及本地边界修复
├── internal/ocsp/                   x/crypto OCSP 实现及 smx509/SM2 适配
└── internal/pkcs12/                 emmansun 国密实现及补入的输入边界修复
```

## 解析链路

```text
Open(data, OpenOptions)
    -> Detect 按 magic、PEM block、ASN.1 结构和 OID 识别格式
    -> 对应格式解码器
    -> Certificate 和 PrivateKey 按 DER 指纹去重
    -> 公钥匹配证书与私钥
    -> 签名、Issuer/Subject、AKI/SKI 构造证书链
    -> Store
```

JKS 首先验证 store digest。密码错误时，已经安全读取的证书条目进入部分 `Store`，私钥保持不可用，并返回包装 `ErrPassword` 的错误。结构损坏不会作为密码错误处理，也不会返回未确认边界的数据。

## 编码链路

```text
Store.Encode(format, EncodeOptions)
    -> 校验目标格式约束和显式密码
    -> 校验 alias、私钥与叶子证书匹配关系
    -> 拒绝未授权的有损转换
    -> 编码数据和 ConversionReport
```

- 标准 PKCS12 使用 SSLMate 的安全修复版本和 `Modern2026`。
- 国密 PKCS12 使用 emmansun 的 SM2/SM3/SM4 实现。
- JKS 私钥始终写成 PKCS#8，证书类型写成 `X.509`。
- PKCS7 只承载证书集合。

## CA 和吊销链路

```text
CreateRootCA / IssueCertificate / SignCertificateRequest
    -> 生成或验证公钥
    -> 设置 SKI、AKI、BasicConstraints、KeyUsage 和有效期
    -> smx509 创建 RSA、ECDSA 或 SM2 证书

CheckCRL / CheckOCSP
    -> 校验签发者关系和签名
    -> 校验序列号、更新时间和吊销状态
```

`FetchAndCheckCRL` 和 `FetchAndCheckOCSP` 是唯一主动访问网络的吊销方法。解析、编码、签发、根库构造和本地验证不访问外部系统。

## TLS 探测链路

```text
InspectTLS(ctx, address, TLSOptions)
    -> TLS 1.0、1.1、1.2、1.3 分别固定 MinVersion/MaxVersion
    -> 使用 SNI 收集服务端证书和 stapled OCSP
    -> smx509 执行主机名及信任链验证
    -> 每个版本返回独立 TLSVersionResult
```

证书收集握手使用 `InsecureSkipVerify`，但握手成功不代表验证成功。最终结果中的 `HostnameValid`、`Trusted` 和 `ServedChainComplete` 来自独立的手工验证。

## 主要依赖关系

```text
certkit ──> core/errx
        ├─> emmansun/gmsm        RSA、ECDSA、SM2 X.509、PKCS7、PKCS8
        ├─> sslmate/go-pkcs12    标准 PKCS12
        ├─> keystore-go          JKS
        └─> x/crypto/x509roots   内嵌 Mozilla 根证书

internal/ber    ──> Mozilla PKCS7 v0.10.0
internal/ocsp   ──> x/crypto/ocsp v0.57.0
internal/pkcs12 ──> emmansun/go-pkcs12 v0.4.2
```

第三方内部实现的许可证、基线版本和本地补丁见对应目录的 `LICENSE`、`UPSTREAM.md` 及 `DEPENDENCIES.md`。

## 自动化流程

- 推送到 `master` 时校验依赖文件，然后运行 lint、本地确定性测试和公网互操作测试。
- 公网互操作测试允许失败，但会在 GitHub Actions 中保留失败步骤和日志。
- 推送 `v*` Tag 时先执行相同检查，再使用对应远端 Tag 创建 GitHub Release。

## 测试结构

- `ca_chain_test.go` 覆盖 RSA、ECDSA、SM2 签发、交叉签名、多路径建链、CRL 和 OCSP。
- `formats_test.go` 覆盖 PEM、DER、PKCS7、PKCS12、JKS、密码错误部分结果和不支持格式。
- `tls_test.go` 使用本地 TLS 服务覆盖分版本握手、SNI 和服务端链完整性。
- `network_test.go` 仅在显式设置 `CERTKIT_NETWORK_TESTS=1` 时访问公开 CA 测试站点。
- `internal` 测试覆盖 BER 边界和 PKCS12 输入安全补丁，不输出私钥或完整证书材料。

## 验证边界

- `make lint` 会先执行 `go mod tidy`，然后运行 golangci-lint。
- `make test` 使用竞态检测运行本地确定性测试，不访问外部服务。
- `make test-network` 会访问公开 TLS 和 CRL 服务，其失败不能单独证明代码回归。
- 静态检查和编译成功不能证明公网 CA、操作系统根库或其他语言密钥库的运行时兼容性。
