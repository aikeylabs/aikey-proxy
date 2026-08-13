package apphook

// childhook_maskmeta_test.go — B3 (2026-08-08) v4 wire fixture: pins the
// proxy-side decode of the detector's response payload BYTE layout and the
// restorable-mask JSON field names. If either side drifts (field rename,
// section reorder), this goes red without needing the detector binary.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// encodeV4ResponsePayload mirrors the detector's pipe.EncodeResponse (v4).
func encodeV4ResponsePayload(reqID uint32, action byte, findings, maskmeta, event []byte) []byte {
	buf := make([]byte, 13+len(findings)+len(maskmeta)+len(event))
	binary.LittleEndian.PutUint32(buf[0:4], reqID)
	buf[4] = action
	binary.LittleEndian.PutUint32(buf[5:9], uint32(len(findings)))
	off := 9 + copy(buf[9:], findings)
	binary.LittleEndian.PutUint32(buf[off:off+4], uint32(len(maskmeta)))
	off += 4
	off += copy(buf[off:], maskmeta)
	copy(buf[off:], event)
	return buf
}

func TestDecodeChildResponsePayload_V4Sections(t *testing.T) {
	findings := []byte("masked [地址(已隐藏)] text")
	meta := []byte(`{"restorables":[{"token":"[地址(已隐藏)]","numbered_prefix":"[地址#","numbered_suffix":"(已隐藏)]","spans":[[7,40]]}]}`)
	event := []byte(`{"event_id":"e1"}`)

	reqID, resp, ok := decodeChildResponsePayload(encodeV4ResponsePayload(77, 1, findings, meta, event))
	if !ok || reqID != 77 || resp.action != 1 {
		t.Fatalf("decode failed: ok=%v reqID=%d resp=%+v", ok, reqID, resp)
	}
	if !bytes.Equal(resp.findings, findings) || !bytes.Equal(resp.maskmeta, meta) || !bytes.Equal(resp.event, event) {
		t.Fatalf("section split wrong: %+v", resp)
	}

	// Field-name pin: the JSON must decode into the proxy's mirror struct with
	// every field populated (a silent tag drift zeroes fields — 失败要显眼).
	var m wireMaskMeta
	if err := json.Unmarshal(resp.maskmeta, &m); err != nil {
		t.Fatalf("maskmeta unmarshal: %v", err)
	}
	if len(m.Restorables) != 1 {
		t.Fatalf("restorables = %d", len(m.Restorables))
	}
	r := m.Restorables[0]
	if r.Token == "" || r.NumberedPrefix == "" || r.NumberedSuffix == "" || len(r.Spans) != 1 || r.Spans[0] != [2]int{7, 40} {
		t.Fatalf("wire field names drifted (zeroed fields): %+v", r)
	}
}

func TestDecodeChildResponsePayload_MalformedDropped(t *testing.T) {
	cases := [][]byte{
		nil,
		make([]byte, 12), // shorter than v4 minimum
		func() []byte { // findings_len overruns
			b := encodeV4ResponsePayload(1, 0, []byte("x"), nil, nil)
			binary.LittleEndian.PutUint32(b[5:9], 999)
			return b
		}(),
		func() []byte { // maskmeta_len overruns
			b := encodeV4ResponsePayload(1, 0, nil, []byte("m"), nil)
			binary.LittleEndian.PutUint32(b[9:13], 999)
			return b
		}(),
	}
	for i, c := range cases {
		if _, _, ok := decodeChildResponsePayload(c); ok {
			t.Fatalf("case %d: malformed payload accepted", i)
		}
	}
}
