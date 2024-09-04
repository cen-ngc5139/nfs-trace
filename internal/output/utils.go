package output

import (
	"bytes"
	"encoding/binary"
	"github.com/cilium/ebpf/perf"
	"github.com/pkg/errors"
	"strings"
)

func parseEvent(rd *perf.Reader, data interface{}) error {
	record, err := rd.Read()
	if err != nil {
		return err
	}

	if record.RawSample == nil {
		return errors.New("record.RawSample is nil")
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, data); err != nil {
		return err
	}

	return nil
}

func convertInt8ToString(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return string(ba)
}

func parseFileName(bs []int8) string {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return strings.ReplaceAll(filterNonASCII(ba), "//", "/")
}

func filterNonASCII(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 { // 只保留可见 ASCII 字符
			sb.WriteByte(b)
		}
	}
	return sb.String()
}
