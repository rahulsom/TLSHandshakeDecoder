package TLSHandshakeDecoder

import (
	_ "bytes"
	"errors"
	"fmt"
)

type TLSRecordLayer struct {
	ContentType uint8
	Version     uint16
	Length 		uint16
	Fragment    []byte
}

func DecodeRecord(p *TLSRecordLayer, data []byte) error {
	if len(data) < 5 {
		return errors.New("Payload too short to be a TLS packet.")
	}

	p.ContentType = uint8(data[0])
	p.Version = uint16(data[1])<<8 | uint16(data[2])
	p.Length = uint16(data[3])<<8 | uint16(data[4])

	p.Fragment = make([]byte, p.Length)
	l := copy(p.Fragment, data[5:5+p.Length])
	if l < int(p.Length) {
		return fmt.Errorf("Payload to short: copied %d, expected %d.", l, p.Length)
	}

	return nil
}
