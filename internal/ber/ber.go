// Copyright (c) 2015 Andrew Smith
// Use of this source code is governed by the MIT license in LICENSE.

package ber

import (
	"bytes"
	"errors"
)

type asn1Object interface {
	EncodeTo(writer *bytes.Buffer) error
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func (s asn1Structured) EncodeTo(out *bytes.Buffer) error {
	inner := new(bytes.Buffer)
	for _, obj := range s.content {
		err := obj.EncodeTo(inner)
		if err != nil {
			return err
		}
	}
	out.Write(s.tagBytes)
	if err := encodeLength(out, inner.Len()); err != nil {
		return err
	}
	out.Write(inner.Bytes())
	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	length   int
	content  []byte
}

func (p asn1Primitive) EncodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, p.length); err != nil {
		return err
	}
	out.Write(p.content)
	return nil
}

// ToDER 在 ASN.1 解码前校验 BER 边界并转换为 DER。
func ToDER(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: input ber is empty")
	}
	out := new(bytes.Buffer)

	obj, offset, err := readObject(ber, 0, 0)
	if err != nil {
		return nil, err
	}
	if offset != len(ber) {
		return nil, errors.New("ber2der: trailing data found")
	}
	if err := obj.EncodeTo(out); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func marshalLongLength(out *bytes.Buffer, i int) (err error) {
	n := lengthLength(i)

	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}

	return nil
}

func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

func encodeLength(out *bytes.Buffer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		err = out.WriteByte(0x80 | byte(l))
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		err = out.WriteByte(byte(length))
		if err != nil {
			return
		}
	}
	return
}

func readObject(ber []byte, offset, depth int) (asn1Object, int, error) {
	if depth > 128 {
		return nil, 0, errors.New("ber2der: maximum nesting depth exceeded")
	}
	berLen := len(ber)
	if offset >= berLen {
		return nil, 0, errors.New("ber2der: offset is after end of ber data")
	}
	tagStart := offset
	b := ber[offset]
	offset++
	if offset >= berLen {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		tag = 0
		for ber[offset] >= 0x80 {
			tag = tag*128 + ber[offset] - 0x80
			offset++
			if offset >= berLen {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
		offset++
		if offset >= berLen {
			return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
		}
	}
	tagEnd := offset

	kind := b & 0x20
	var length int
	l := ber[offset]
	offset++
	if offset > berLen {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	indefinite := false
	if l > 0x80 {
		numberOfBytes := (int)(l & 0x7F)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, 0, errors.New("ber2der: BER tag length too long")
		}
		if offset+numberOfBytes > berLen {
			return nil, 0, errors.New("ber2der: BER tag length is more than available data")
		}
		if numberOfBytes == 4 && (int)(ber[offset]) > 0x7F {
			return nil, 0, errors.New("ber2der: BER tag length is negative")
		}
		if (int)(ber[offset]) == 0x0 {
			return nil, 0, errors.New("ber2der: BER tag length has leading zero")
		}
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + (int)(ber[offset])
			offset++
			if offset > berLen {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
	} else if l == 0x80 {
		indefinite = true
	} else {
		length = (int)(l)
	}
	if length < 0 {
		return nil, 0, errors.New("ber2der: invalid negative value found in BER tag length")
	}
	contentEnd := offset + length
	if contentEnd > len(ber) {
		return nil, 0, errors.New("ber2der: BER tag length is more than available data")
	}
	var obj asn1Object
	if indefinite && kind == 0 {
		return nil, 0, errors.New("ber2der: Indefinite form tag must have constructed encoding")
	}
	if kind == 0 {
		obj = asn1Primitive{
			tagBytes: ber[tagStart:tagEnd],
			length:   length,
			content:  ber[offset:contentEnd],
		}
	} else {
		var subObjects []asn1Object
		for (offset < contentEnd) || indefinite {
			if indefinite {
				terminated, err := isIndefiniteTermination(ber, offset)
				if err != nil {
					return nil, 0, err
				}
				if terminated {
					offset += 2
					break
				}
			}
			var subObj asn1Object
			var err error
			subObj, offset, err = readObject(ber, offset, depth+1)
			if err != nil {
				return nil, 0, err
			}
			if !indefinite && offset > contentEnd {
				return nil, 0, errors.New("ber2der: child object exceeds parent boundary")
			}
			subObjects = append(subObjects, subObj)
		}
		obj = asn1Structured{
			tagBytes: ber[tagStart:tagEnd],
			content:  subObjects,
		}
	}

	if indefinite {
		contentEnd = offset
	}

	return obj, contentEnd, nil
}

func isIndefiniteTermination(ber []byte, offset int) (bool, error) {
	if len(ber)-offset < 2 {
		return false, errors.New("ber2der: Invalid BER format")
	}

	return bytes.Index(ber[offset:], []byte{0x0, 0x0}) == 0, nil
}
