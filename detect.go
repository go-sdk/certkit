package certkit

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"

	"github.com/emmansun/gmsm/smx509"

	"github.com/go-sdk/certkit/internal/ber"
)

var (
	oidPKCS7Data          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidPKCS7EnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
)

type contentInfoHeader struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type pfxHeader struct {
	Version  int
	AuthSafe contentInfoHeader
	MACData  asn1.RawValue `asn1:"optional"`
}

// Detect 根据内容识别证书或密钥容器格式，不依赖文件扩展名。
func Detect(data []byte) (Detection, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return Detection{Format: FormatUnknown, Encoding: EncodingUnknown}, ErrUnknownFormat
	}
	if block, _ := pem.Decode(data); block != nil {
		return Detection{Format: detectPEMBlock(block), Encoding: EncodingPEM, Confidence: ConfidenceHigh}, nil
	}
	if len(data) >= 4 {
		switch binary.BigEndian.Uint32(data[:4]) {
		case 0xfeedfeed:
			return Detection{Format: FormatJKS, Encoding: EncodingDER, Confidence: ConfidenceHigh}, nil
		case 0xcececece:
			return Detection{Format: FormatJCEKS, Encoding: EncodingDER, Confidence: ConfidenceHigh}, nil
		}
	}
	if looksLikeBKS(data) {
		return Detection{Format: FormatBKS, Encoding: EncodingDER, Confidence: ConfidenceMedium}, nil
	}
	var pfx pfxHeader
	if rest, err := asn1.Unmarshal(data, &pfx); err == nil && len(rest) == 0 && pfx.Version == 3 && pfx.AuthSafe.ContentType.Equal(oidPKCS7Data) {
		return Detection{Format: FormatPKCS12, Encoding: EncodingDER, Confidence: ConfidenceHigh}, nil
	}
	var contentInfo contentInfoHeader
	if rest, err := asn1.Unmarshal(data, &contentInfo); err == nil && len(rest) == 0 && isPKCS7ContentType(contentInfo.ContentType) {
		return Detection{Format: FormatPKCS7, Encoding: EncodingDER, Confidence: ConfidenceHigh}, nil
	}
	if der, err := ber.ToDER(data); err == nil {
		if rest, unmarshalErr := asn1.Unmarshal(der, &contentInfo); unmarshalErr == nil && len(rest) == 0 && isPKCS7ContentType(contentInfo.ContentType) {
			return Detection{Format: FormatPKCS7, Encoding: EncodingDER, Confidence: ConfidenceHigh}, nil
		}
	}
	if _, err := smx509.ParseCertificate(data); err == nil {
		return Detection{Format: FormatDER, Encoding: EncodingDER, Confidence: ConfidenceHigh}, nil
	}
	if _, err := parsePrivateKey(data, nil); err == nil {
		return Detection{Format: FormatDER, Encoding: EncodingDER, Confidence: ConfidenceHigh}, nil
	}
	return Detection{Format: FormatUnknown, Encoding: EncodingUnknown}, ErrUnknownFormat
}

func detectPEMBlock(block *pem.Block) Format {
	switch block.Type {
	case "PKCS7", "PKCS #7 SIGNED DATA", "CMS":
		return FormatPKCS7
	case "PKCS12", "PFX":
		return FormatPKCS12
	default:
		return FormatPEM
	}
}

func isPKCS7ContentType(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidPKCS7Data) || oid.Equal(oidPKCS7SignedData) || oid.Equal(oidPKCS7EnvelopedData)
}

func looksLikeBKS(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	version := binary.BigEndian.Uint32(data[:4])
	if version != 1 && version != 2 {
		return false
	}
	saltLength := binary.BigEndian.Uint32(data[4:8])
	if saltLength == 0 || saltLength > 1<<20 || uint64(12)+uint64(saltLength)+20 > uint64(len(data)) {
		return false
	}
	offset := 8 + int(saltLength)
	iterations := binary.BigEndian.Uint32(data[offset : offset+4])
	return iterations > 0 && iterations <= 100_000_000
}
