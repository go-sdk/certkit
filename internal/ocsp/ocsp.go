// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license in LICENSE.

package ocsp

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

var (
	oidBasicResponse   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSHA1            = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSM2WithSM3      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	oidRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
)

const (
	Good    = 0
	Revoked = 1
	Unknown = 2
)

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type ocspRequest struct {
	TBSRequest tbsRequest
}

type tbsRequest struct {
	Version     int `asn1:"explicit,tag:0,default:0,optional"`
	RequestList []request
}

type request struct {
	Cert certID
}

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []singleResponse
}

type singleResponse struct {
	CertID           certID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type pssParameters struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0,optional"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1,optional"`
	SaltLength   int                      `asn1:"explicit,tag:2,optional"`
	TrailerField int                      `asn1:"explicit,tag:3,optional"`
}

type Response struct {
	Status           int
	SerialNumber     *big.Int
	ProducedAt       time.Time
	ThisUpdate       time.Time
	NextUpdate       time.Time
	RevokedAt        time.Time
	RevocationReason int
}

func CreateRequest(cert, issuer *smx509.Certificate, hash crypto.Hash) ([]byte, error) {
	if cert == nil || issuer == nil {
		return nil, errors.New("certificate and issuer are required")
	}
	if hash == 0 {
		hash = crypto.SHA1
	}
	hashOID := hashOID(hash)
	if hashOID == nil || !hash.Available() {
		return nil, smx509.ErrUnsupportedAlgorithm
	}
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, err
	}
	digest := hash.New()
	_, _ = digest.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := digest.Sum(nil)
	digest.Reset()
	_, _ = digest.Write(issuer.RawSubject)
	issuerNameHash := digest.Sum(nil)
	identifier := certID{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: hashOID, Parameters: asn1.NullRawValue},
		NameHash:      issuerNameHash,
		IssuerKeyHash: issuerKeyHash,
		SerialNumber:  cert.SerialNumber,
	}
	return asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{RequestList: []request{{Cert: identifier}}}})
}

func ParseResponseForCert(data []byte, cert, issuer *smx509.Certificate) (*Response, error) {
	var outer responseASN1
	rest, err := asn1.Unmarshal(data, &outer)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid OCSP response")
	}
	if outer.Status != 0 {
		return nil, errors.New("OCSP responder returned an error")
	}
	if !outer.Response.ResponseType.Equal(oidBasicResponse) {
		return nil, errors.New("unsupported OCSP response type")
	}
	var basic basicResponse
	rest, err = asn1.Unmarshal(outer.Response.Response, &basic)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid basic OCSP response")
	}
	if len(basic.TBSResponseData.Responses) == 0 {
		return nil, errors.New("OCSP response contains no certificate status")
	}
	var selected *singleResponse
	for i := range basic.TBSResponseData.Responses {
		candidate := &basic.TBSResponseData.Responses[i]
		if cert == nil || cert.SerialNumber.Cmp(candidate.CertID.SerialNumber) == 0 {
			selected = candidate
			break
		}
	}
	if selected == nil {
		return nil, errors.New("OCSP response does not contain the requested certificate")
	}
	if issuer != nil {
		if err := verifyCertID(selected.CertID, issuer); err != nil {
			return nil, err
		}
	}
	for _, extension := range selected.SingleExtensions {
		if extension.Critical {
			return nil, errors.New("OCSP response contains an unsupported critical extension")
		}
	}
	signatureAlgorithm := signatureAlgorithm(basic.SignatureAlgorithm)
	if signatureAlgorithm == smx509.UnknownSignatureAlgorithm {
		return nil, smx509.ErrUnsupportedAlgorithm
	}
	signer := issuer
	if len(basic.Certificates) > 0 {
		signer, err = smx509.ParseCertificate(basic.Certificates[0].FullBytes)
		if err != nil {
			return nil, err
		}
		if issuer != nil {
			if err := signer.CheckSignatureFrom(issuer); err != nil {
				return nil, errors.New("OCSP responder certificate is not signed by issuer")
			}
			if !hasOCSPSigningUsage(signer) {
				return nil, errors.New("OCSP responder certificate is not allowed to sign responses")
			}
		}
	}
	if signer == nil {
		return nil, errors.New("OCSP response signer is unavailable")
	}
	if basic.TBSResponseData.ProducedAt.Before(signer.NotBefore) || basic.TBSResponseData.ProducedAt.After(signer.NotAfter) {
		return nil, errors.New("OCSP responder certificate is not valid at producedAt")
	}
	if err := signer.CheckSignature(signatureAlgorithm, basic.TBSResponseData.Raw, basic.Signature.RightAlign()); err != nil {
		return nil, errors.New("invalid OCSP response signature")
	}
	result := &Response{
		SerialNumber: selected.CertID.SerialNumber,
		ProducedAt:   basic.TBSResponseData.ProducedAt,
		ThisUpdate:   selected.ThisUpdate,
		NextUpdate:   selected.NextUpdate,
	}
	switch {
	case bool(selected.Good):
		result.Status = Good
	case bool(selected.Unknown):
		result.Status = Unknown
	default:
		result.Status = Revoked
		result.RevokedAt = selected.Revoked.RevocationTime
		result.RevocationReason = int(selected.Revoked.Reason)
	}
	return result, nil
}

func hashOID(hash crypto.Hash) asn1.ObjectIdentifier {
	switch hash {
	case crypto.SHA1:
		return oidSHA1
	case crypto.SHA256:
		return oidSHA256
	case crypto.SHA384:
		return oidSHA384
	case crypto.SHA512:
		return oidSHA512
	default:
		return nil
	}
}

func hashFromOID(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1
	case oid.Equal(oidSHA256):
		return crypto.SHA256
	case oid.Equal(oidSHA384):
		return crypto.SHA384
	case oid.Equal(oidSHA512):
		return crypto.SHA512
	default:
		return 0
	}
}

func verifyCertID(id certID, issuer *smx509.Certificate) error {
	hash := hashFromOID(id.HashAlgorithm.Algorithm)
	if hash == 0 || !hash.Available() {
		return errors.New("unsupported OCSP issuer hash algorithm")
	}
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return err
	}
	digest := hash.New()
	_, _ = digest.Write(publicKeyInfo.PublicKey.RightAlign())
	if !bytes.Equal(digest.Sum(nil), id.IssuerKeyHash) {
		return errors.New("OCSP issuer key hash does not match")
	}
	digest.Reset()
	_, _ = digest.Write(issuer.RawSubject)
	if !bytes.Equal(digest.Sum(nil), id.NameHash) {
		return errors.New("OCSP issuer name hash does not match")
	}
	return nil
}

func signatureAlgorithm(identifier pkix.AlgorithmIdentifier) smx509.SignatureAlgorithm {
	oid := identifier.Algorithm
	switch {
	case oid.Equal(oidSHA1WithRSA):
		return smx509.SHA1WithRSA
	case oid.Equal(oidSHA256WithRSA):
		return smx509.SHA256WithRSA
	case oid.Equal(oidSHA384WithRSA):
		return smx509.SHA384WithRSA
	case oid.Equal(oidSHA512WithRSA):
		return smx509.SHA512WithRSA
	case oid.Equal(oidECDSAWithSHA1):
		return smx509.ECDSAWithSHA1
	case oid.Equal(oidECDSAWithSHA256):
		return smx509.ECDSAWithSHA256
	case oid.Equal(oidECDSAWithSHA384):
		return smx509.ECDSAWithSHA384
	case oid.Equal(oidECDSAWithSHA512):
		return smx509.ECDSAWithSHA512
	case oid.Equal(oidSM2WithSM3):
		return smx509.SM2WithSM3
	case oid.Equal(oidEd25519):
		return smx509.PureEd25519
	case oid.Equal(oidRSAPSS):
		var parameters pssParameters
		if _, err := asn1.Unmarshal(identifier.Parameters.FullBytes, &parameters); err != nil {
			return smx509.UnknownSignatureAlgorithm
		}
		switch {
		case parameters.Hash.Algorithm.Equal(oidSHA256):
			return smx509.SHA256WithRSAPSS
		case parameters.Hash.Algorithm.Equal(oidSHA384):
			return smx509.SHA384WithRSAPSS
		case parameters.Hash.Algorithm.Equal(oidSHA512):
			return smx509.SHA512WithRSAPSS
		default:
			return smx509.UnknownSignatureAlgorithm
		}
	default:
		return smx509.UnknownSignatureAlgorithm
	}
}

func hasOCSPSigningUsage(cert *smx509.Certificate) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == smx509.ExtKeyUsageOCSPSigning || usage == smx509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
