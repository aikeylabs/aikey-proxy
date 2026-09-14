package deepscanfwd

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// unixSinkV2 talks to the on-machine deep-scan daemon over a unix socket and
// reads the RESULT frame back on the same connection.
//
// 🔴 HOW THIS DIFFERS FROM pkg/deepscan's v1 unix sink, and why both exist: the
// v1 sink is fire-and-forget — it writes and never reads, because in v1 the
// DAEMON uploaded its own findings. From v1.1 the proxy is the only party that
// may upload (it is the only one that knows the seat, session and trace), so the
// daemon has to hand results back, and this sink has to read them. The v1 sink
// stays because an OLD proxy still talks to a NEW daemon during a rollout.
//
// 🚫 No token. Same machine, same trust domain, same user — there is nothing to
// authorize against, and a credential on this path would be one more place a
// secret lives for no benefit (design §4b.5).
type unixSinkV2 struct {
	path          string
	dialTimeout   time.Duration
	resultTimeout time.Duration
	results       chan deepscan.ResultFrame

	mu   sync.Mutex
	conn net.Conn
}

// NewUnixSinkV2 returns a Sink that writes v2 frames to the daemon socket and
// publishes the result frames it reads back.
func NewUnixSinkV2(path string, resultTimeout time.Duration) deepscan.Sink {
	if resultTimeout <= 0 {
		resultTimeout = 30 * time.Second
	}
	return &unixSinkV2{
		path: path, dialTimeout: 2 * time.Second, resultTimeout: resultTimeout,
		results: make(chan deepscan.ResultFrame, 64),
	}
}

// Results yields result frames read back from the daemon.
func (s *unixSinkV2) Results() <-chan deepscan.ResultFrame { return s.results }

func (s *unixSinkV2) Send(ctx context.Context, frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		d := net.Dialer{Timeout: s.dialTimeout}
		c, err := d.DialContext(ctx, "unix", s.path)
		if err != nil {
			// A missing socket is the NORMAL state on a machine with no daemon
			// installed. The caller turns this into reason=local_daemon_absent in
			// the health section rather than an error anyone must act on.
			return fmt.Errorf("deepscan v2 dial %s: %w", s.path, err)
		}
		s.conn = c
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.dialTimeout))
	if _, err := s.conn.Write(frame); err != nil {
		s.reset()
		return fmt.Errorf("deepscan v2 write %s: %w", s.path, err)
	}

	res, err := s.readResult()
	if err != nil {
		s.reset()
		return err
	}
	select {
	case s.results <- res:
	default:
		// Nobody draining — drop rather than stall the delivery worker. The
		// forwarder's counters carry the loss.
	}
	return nil
}

// readResult reads exactly one framed result. The framing lives in
// deepscan.ReadResult, shared with the TLS sink so the two cannot drift.
func (s *unixSinkV2) readResult() (deepscan.ResultFrame, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(s.resultTimeout))
	return deepscan.ReadResult(s.conn)
}

func (s *unixSinkV2) reset() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

func (s *unixSinkV2) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reset()
	return nil
}
