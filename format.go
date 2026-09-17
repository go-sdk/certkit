package certkit

// Format 表示证书或密钥容器格式。
type Format string

const (
	FormatAuto    Format = "auto"
	FormatUnknown Format = "unknown"
	FormatPEM     Format = "pem"
	FormatDER     Format = "der"
	FormatPKCS7   Format = "pkcs7"
	FormatPKCS12  Format = "pkcs12"
	FormatJKS     Format = "jks"
	FormatJCEKS   Format = "jceks"
	FormatBKS     Format = "bks"
)

// Encoding 表示输入或输出的外层编码。
type Encoding string

const (
	EncodingUnknown Encoding = "unknown"
	EncodingPEM     Encoding = "pem"
	EncodingDER     Encoding = "der"
)

// Confidence 表示内容格式检测结果的可信程度。
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Detection 描述基于内容识别出的格式、编码和候选格式。
type Detection struct {
	Format       Format
	Encoding     Encoding
	Confidence   Confidence
	Alternatives []Format
}
