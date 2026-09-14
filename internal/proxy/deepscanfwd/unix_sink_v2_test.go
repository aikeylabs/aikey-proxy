package deepscanfwd

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// TestUnixSinkV2_RoundTripsResultAndCarriesNoToken drives a real unix socket
// with a stand-in daemon that decodes the v2 frame and answers with a result.
func TestUnixSinkV2_RoundTripsResultAndCarriesNoToken(t *testing.T) {
	sock := shortSocketPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	gotFrame := make(chan deepscan.FrameV2, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var head [5]byte
		if _, err := io.ReadFull(c, head[:]); err != nil {
			return
		}
		n := binary.LittleEndian.Uint32(head[1:5])
		body := make([]byte, n)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		f, err := deepscan.DecodeFrameV2(append(head[:], body...))
		if err != nil {
			return
		}
		gotFrame <- f
		out, _ := deepscan.EncodeResult(deepscan.ResultFrame{
			JobID: f.JobID, Status: deepscan.StatusComplete,
			ScannedBytes: len(f.Prompt), TotalBytes: len(f.Prompt),
			Findings: []deepscan.Finding{{
				Engine: deepscan.EngineRules, EntityType: "CN_PHONE", Category: "pii",
				Severity: "high", Confidence: 95, Start: 6, End: 17,
			}},
		})
		_, _ = c.Write(out)
	}()

	sink := NewUnixSinkV2(sock, 3*time.Second)
	defer sink.Close()

	frame, _ := BuildFrame(PieceJob{
		JobID: "job-local-1", TenantID: "org_a", AuditUnitID: "au_1", ContentSHA256: "sha",
		Source: deepscan.SourceRequest, Text: "客户手机号 13800138000", HeadBytes: 0,
		Engines: []string{deepscan.EngineRules},
	}, "", DefaultMaxPieceBytes) // empty token: local path

	b, err := deepscan.EncodeFrameV2(frame)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.Contains(string(b), `"token"`) {
		t.Errorf("the local frame carries a token; there is nothing to authorize against on the same machine: %s", b)
	}
	if err := sink.Send(context.Background(), b); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case f := <-gotFrame:
		if f.JobID != "job-local-1" || f.TenantID != "org_a" {
			t.Errorf("daemon received a mangled frame: %+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the daemon never received the frame")
	}

	res := sink.(*unixSinkV2).Results()
	select {
	case r := <-res:
		if r.JobID != "job-local-1" {
			t.Errorf("result job_id = %q", r.JobID)
		}
		if len(r.Findings) != 1 || r.Findings[0].EntityType != "CN_PHONE" {
			t.Errorf("the result's findings did not survive: %+v", r.Findings)
		}
	case <-time.After(time.Second):
		t.Fatal("no result was published — the v1 fire-and-forget behaviour would look exactly like this, " +
			"and the async lane would produce no audit rows at all")
	}
}

// TestUnixSinkV2_MissingSocketIsAnOrdinaryError: a machine with no daemon is the
// normal Personal case, not an incident.
func TestUnixSinkV2_MissingSocketIsAnOrdinaryError(t *testing.T) {
	sink := NewUnixSinkV2(shortSocketPath(t)+".absent", time.Second)
	defer sink.Close()
	err := sink.Send(context.Background(), []byte{2, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("sending to a missing socket must return an error")
	}
	if !strings.Contains(err.Error(), "dial") {
		t.Errorf("the error should say it could not dial, so the caller can map it to local_daemon_absent: %v", err)
	}
}

// shortSocketPath returns a path short enough for a unix socket.
//
// macOS caps sockaddr_un.sun_path at 104 bytes, and Go's t.TempDir() embeds the
// full test name — which for these tests is already longer than that, so
// net.Listen fails with a bare "invalid argument" that looks like a code bug
// rather than a path-length limit.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ds")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := filepath.Join(dir, "s")
	if len(p) > 100 {
		t.Fatalf("socket path is still %d bytes, over the platform limit: %s", len(p), p)
	}
	return p
}
