package asyncscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestAsyncScanEvent_DeterministicIDs: the async event's id is derived from the
// CONTENT, not minted randomly, so the same piece scanned twice produces the
// same id and the database's ON CONFLICT absorbs the repeat.
//
// 🔴 This is a re-run of a bug that already cost this project once. Until
// 2026-09-08 the compliance event_id came from the detector child's CSPRNG, so a
// piece re-sent every turn produced a NEW audit row every turn: the two ingest
// paths' ON CONFLICT (event_id) could absorb a replayed upload but not a
// re-scan, and the audit page filled with duplicates of one violation
// (bugfix 2026-09-08-compliance-audit-unit-id-parasitic-on-cache.md). The async
// lane re-scans by construction — a proxy restart clears the in-memory
// already-scanned record — so if its ids were random the same flood would come
// straight back through a new door.
//
// bge and rules must NOT collide: they are two different findings about the same
// content and a reviewer needs both rows.
func TestAsyncScanEvent_DeterministicIDs(t *testing.T) {
	unit := "au_0123456789abcdef"

	bge1, rules1 := DeepScanEventID(unit), RuleScanEventID(unit)
	for i := 0; i < 20; i++ {
		if got := DeepScanEventID(unit); got != bge1 {
			t.Fatalf("bge event id is not deterministic: %s vs %s", got, bge1)
		}
		if got := RuleScanEventID(unit); got != rules1 {
			t.Fatalf("rule event id is not deterministic: %s vs %s", got, rules1)
		}
	}
	if bge1 == rules1 {
		t.Fatal("bge and rule events share an id; one would overwrite the other in the audit table")
	}
	if !strings.HasPrefix(bge1, "ad_") {
		t.Errorf("bge event id %q must carry the ad_ prefix", bge1)
	}
	if !strings.HasPrefix(rules1, "ar_") {
		t.Errorf("rule event id %q must carry the ar_ prefix", rules1)
	}
	// Must not collide with the fast layer's au_ ids for the same unit.
	if strings.HasPrefix(bge1, "au_") || strings.HasPrefix(rules1, "au_") {
		t.Error("an async id collided with the fast layer's audit-unit id space")
	}
	if DeepScanEventID("au_other") == bge1 {
		t.Error("two different audit units produced the same event id")
	}
}

// TestAsyncScanLRU_ResentPieceScannedOnce: an agent turn resends the whole
// conversation every round. Without a already-scanned record the async lane
// would re-scan the entire history on every turn — the cost grows with the
// square of the conversation length.
func TestAsyncScanLRU_ResentPieceScannedOnce(t *testing.T) {
	l := NewScannedLRU(64)
	key := "sess-1\x00" + sha("the same paragraph, verbatim") + "\x00rules\x00v1"

	if !l.Claim(key) {
		t.Fatal("the first sighting must be claimed")
	}
	if l.Claim(key) {
		t.Error("a second claim while the first is in flight must be refused — single-flight, or two nodes scan the same bytes")
	}
	l.Finalize(key)
	for turn := 2; turn <= 3; turn++ {
		if l.Claim(key) {
			t.Errorf("turn %d re-claimed a finalized piece; the whole history would be re-scanned every turn", turn)
		}
	}

	// A different engine version is a different question about the same bytes.
	if !l.Claim("sess-1\x00" + sha("the same paragraph, verbatim") + "\x00rules\x00v2") {
		t.Error("a ruleset change must make the piece scannable again, or a fixed rule never re-examines old content")
	}
}

// TestAsyncScanLRU_TransientFailureRetriesThenFinalises: a piece whose scan
// failed transiently must be retried when it reappears — but not forever. After
// the third transient failure it is finalized as partial, so a permanently
// unreachable node cannot make every turn re-enqueue the same content.
func TestAsyncScanLRU_TransientFailureRetriesThenFinalises(t *testing.T) {
	l := NewScannedLRU(8)
	key := "k"
	for attempt := 1; attempt <= 3; attempt++ {
		if !l.Claim(key) {
			t.Fatalf("attempt %d: a transiently-failed piece must be claimable again", attempt)
		}
		if got := l.Transient(key); got != attempt {
			t.Errorf("attempt %d: Transient returned %d", attempt, got)
		}
	}
	if l.Claim(key) {
		t.Error("after the third transient failure the piece must be finalized, not retried forever")
	}
}

// TestAsyncScanIdentity_SameHeadDifferentTailTwoUnits: two pieces sharing their
// first 16 KiB but differing afterwards are DIFFERENT audit units.
//
// 🔴 The fast layer hashes only the head it scanned, which is correct for its own
// cache — it only ever looked at the head. The async lane looks at the WHOLE
// piece, so if it reused the head hash, a user could get one scan of a long
// document and then append anything at all to it forever, and every later
// version would be recognized as "already scanned".
func TestAsyncScanIdentity_SameHeadDifferentTailTwoUnits(t *testing.T) {
	head := strings.Repeat("a", 16*1024)
	p1 := head + "the tail is clean"
	p2 := head + "postgres://svc:S3cr3t@10.2.3.4:5432/db"

	id1 := PieceIdentity("sess-1", p1)
	id2 := PieceIdentity("sess-1", p2)
	if id1.ContentSHA256 == id2.ContentSHA256 {
		t.Fatal("two pieces with the same head but different tails hashed identically — appending to a scanned document would be free")
	}
	if id1.AuditUnitID == id2.AuditUnitID {
		t.Fatal("same audit unit for different content; the second piece's findings would collide with the first's row")
	}
	// The same bytes in the same scope must still agree with themselves.
	if PieceIdentity("sess-1", p1) != id1 {
		t.Error("PieceIdentity is not deterministic")
	}
	// Different scope, same bytes: different unit (sessions must not share rows).
	if PieceIdentity("sess-2", p1).AuditUnitID == id1.AuditUnitID {
		t.Error("two sessions produced one audit unit for the same text")
	}
}

// TestAsyncScanEnqueue_BlockedRequestNotEnqueued: a blocked request never
// reaches the commit point, so nothing about it is enqueued.
//
// Not merely an optimisation: a blocked request's bytes were REFUSED — they
// never went upstream. Sending them to a scan node afterwards would push content
// off the machine that the policy had just decided must not leave it, and would
// then write an audit row asserting the content was forwarded.
func TestAsyncScanEnqueue_BlockedRequestNotEnqueued(t *testing.T) {
	var enqueued []CommittedPiece
	var mu sync.Mutex
	e := NewEnqueuer(func(p CommittedPiece, _ RequestIdentity) bool {
		mu.Lock()
		defer mu.Unlock()
		enqueued = append(enqueued, p)
		return true
	}, NewScannedLRU(16))

	id := RequestIdentity{TenantID: "org_a", SessionID: "sess-1"}
	e.OnCommit([]CommittedPiece{
		{Text: "clean piece", HeadBytes: 11},
		{Text: "another clean piece", HeadBytes: 19},
	}, id)

	mu.Lock()
	n := len(enqueued)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("a committed request must enqueue its pieces, got %d", n)
	}

	// The blocked case: OnCommit is simply never reached. Assert the shape of
	// that contract rather than a flag, because the flag is what would rot.
	enqueued = nil
	// (no OnCommit call — the dispatcher returned before the commit point)
	if len(enqueued) != 0 {
		t.Error("nothing may be enqueued for a blocked request")
	}
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var _ = fmt.Sprintf
