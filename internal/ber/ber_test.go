package ber

import (
	"bytes"
	"testing"
)

func TestToDERRejectsTrailingAndTruncatedData(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty":          nil,
		"trailing":       {0x30, 0x00, 0x00},
		"truncated":      {0x30, 0x03, 0x02, 0x01},
		"invalid-length": {0x30, 0x82, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ToDER(input); err == nil {
				t.Fatal("invalid BER input was accepted")
			}
		})
	}
}

func TestToDERConvertsIndefiniteLength(t *testing.T) {
	input := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}
	want := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	got, err := ToDER(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected DER output: %x", got)
	}
	empty, err := ToDER([]byte{0x30, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty, []byte{0x30, 0x00}) {
		t.Fatalf("unexpected empty DER output: %x", empty)
	}
}

func TestToDERRejectsExcessiveNesting(t *testing.T) {
	input := []byte{0x02, 0x01, 0x01}
	for range 130 {
		input = append([]byte{0x30, 0x80}, append(input, 0x00, 0x00)...)
	}
	if _, err := ToDER(input); err == nil {
		t.Fatal("excessively nested BER input was accepted")
	}
}
