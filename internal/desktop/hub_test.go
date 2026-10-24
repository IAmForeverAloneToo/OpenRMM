package desktop

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/jpeg"
	"strings"
	"sync"
	"testing"
	"time"
)

const testDevice = "11111111111111111111111111111111"
const testPeer = "22222222222222222222222222222222"

func TestEndReasonsAreOwnedAuthorizedEphemeralAndBounded(t *testing.T) {
	h, now, allowed, _ := testHub(t)
	ctx := context.Background()
	q := start(t, h, true)
	if _, e := h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "denied"}); e != nil {
		t.Fatal(e)
	}
	if h.EndReason(ctx, q.ID, "owner") != "denied" || h.EndReason(ctx, q.ID, "foreign") != "" {
		t.Fatal("end ownership")
	}
	*allowed = false
	if h.EndReason(ctx, q.ID, "owner") != "" {
		t.Fatal("end reason leaked after permission loss")
	}
	*allowed = true
	*now = now.Add(time.Minute)
	if h.EndReason(ctx, q.ID, "owner") != "" {
		t.Fatal("expired end metadata retained")
	}
	for range 70 {
		q = start(t, h, false)
		if e := h.Stop(ctx, q.ID, "owner"); e != nil {
			t.Fatal(e)
		}
	}
	if len(h.ended) > 64 || len(h.sessions) != 0 {
		t.Fatal("unbounded ending state")
	}
	if _, _, e := h.View(ctx, q.ID, "owner"); e == nil {
		t.Fatal("ended media resumed")
	}
}

func testJPEG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if e := jpeg.Encode(&b, image.NewRGBA(image.Rect(0, 0, 16, 16)), nil); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func testHub(t *testing.T) (*Hub, *time.Time, *bool, *[]string) {
	t.Helper()
	now := time.Now()
	allowed := true
	events := []string{}
	h := NewHub(func(_ context.Context, d, o string, _ time.Time) error {
		if !allowed || d != testDevice || o != "owner" {
			return ErrInvalid
		}
		return nil
	}, func(_ context.Context, a, k, target, out string, _ time.Time) error {
		events = append(events, k+":"+out)
		return nil
	})
	h.now = func() time.Time { return now }
	return h, &now, &allowed, &events
}
func start(t *testing.T, h *Hub, control bool) Request {
	t.Helper()
	ctx := context.Background()
	if _, e := h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer}); e != nil {
		t.Fatal(e)
	}
	r, e := h.Create(ctx, testDevice, "owner", "technician", control, 0, "")
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestConsentOwnerDeviceAndNoInputReplay(t *testing.T) {
	h, _, _, events := testHub(t)
	ctx := context.Background()
	q := start(t, h, true)
	b := Batch{Sequence: 1, Events: []Input{{Kind: "text", Text: "literal"}}}
	if e := h.Input(ctx, q.ID, "owner", b); e == nil {
		t.Fatal("input before consent")
	}
	if _, _, e := h.View(ctx, q.ID, "another-browser-session"); e == nil {
		t.Fatal("foreign owner")
	}
	r, e := h.Exchange(ctx, "33333333333333333333333333333333", Exchange{Ready: true, Peer: testPeer})
	if e != nil || r.Request != nil {
		t.Fatal("foreign device")
	}
	r, e = h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer})
	if e != nil || r.Request == nil || r.Request.ID != q.ID || len(r.Inputs) != 0 {
		t.Fatal("dispatch", e)
	}
	frame := testJPEG(t)
	r, e = h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "active", Frame: frame})
	if e != nil || r.Request == nil {
		t.Fatal(e)
	}
	if e = h.Input(ctx, q.ID, "owner", b); e != nil {
		t.Fatal(e)
	}
	if e = h.Input(ctx, q.ID, "owner", b); e == nil {
		t.Fatal("duplicate batch accepted")
	}
	r, e = h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "active"})
	if e != nil || len(r.Inputs) != 1 {
		t.Fatal("input missing", e)
	}
	r, e = h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "active"})
	if e != nil || len(r.Inputs) != 0 {
		t.Fatal("input replayed")
	}
	v, bf, e := h.View(ctx, q.ID, "owner")
	if e != nil || v.State != "active" || !bytes.Equal(bf, frame) {
		t.Fatal("frame missing", e)
	}
	bf[0] = 0
	_, again, _ := h.View(ctx, q.ID, "owner")
	if !bytes.Equal(again, frame) {
		t.Fatal("returned shared media buffer")
	}
	if e = h.Stop(ctx, q.ID, "owner"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = h.View(ctx, q.ID, "owner"); e == nil {
		t.Fatal("session survived stop")
	}
	if len(*events) != 3 {
		t.Fatal("lifecycle audit", *events)
	}
}
func TestViewOnlyDenialDisconnectAndAuthorization(t *testing.T) {
	for _, reason := range []string{"denied", "ended", "unavailable", "reconnect", "revoke", "absence", "reset"} {
		t.Run(reason, func(t *testing.T) {
			h, _, allowed, _ := testHub(t)
			ctx := context.Background()
			q := start(t, h, false)
			_, e := h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "active", Frame: testJPEG(t)})
			if e != nil {
				t.Fatal(e)
			}
			if e = h.Input(ctx, q.ID, "owner", Batch{Sequence: 1, Events: []Input{{Kind: "key", Key: 13}}}); e == nil {
				t.Fatal("view-only input accepted")
			}
			p := Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: reason}
			switch reason {
			case "reconnect":
				p = Exchange{Ready: true, Peer: "44444444444444444444444444444444"}
			case "absence":
				p = Exchange{}
			case "revoke":
				*allowed = false
				p.State = "active"
			case "reset":
				p.State = "waiting"
			}
			r, e := h.Exchange(ctx, testDevice, p)
			if e != nil || r.Request != nil {
				t.Fatal("did not end", e)
			}
			if _, _, e = h.View(ctx, q.ID, "owner"); e == nil {
				t.Fatal("still visible")
			}
		})
	}
}
func TestExpiryFreshnessInputTTLAndBounds(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"viewer", "agent", "consent", "hard"} {
		t.Run(kind, func(t *testing.T) {
			h, now, _, _ := testHub(t)
			q := start(t, h, true)
			s := h.sessions[q.ID]
			switch kind {
			case "viewer":
				*now = now.Add(31 * time.Second)
				s.agent = *now
			case "agent":
				*now = now.Add(11 * time.Second)
				s.viewer = *now
			case "consent":
				*now = now.Add(61 * time.Second)
				s.viewer = *now
				s.agent = *now
			case "hard":
				*now = now.Add(16 * time.Minute)
				s.viewer = *now
				s.agent = *now
				s.state = "active"
			}
			if _, _, e := h.View(ctx, q.ID, "owner"); e == nil {
				t.Fatal("expired session survived", kind)
			}
		})
	}
	h, now, _, _ := testHub(t)
	q := start(t, h, true)
	_, _ = h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "active", Frame: testJPEG(t)})
	for i := uint64(1); i <= 64; i++ {
		if e := h.Input(ctx, q.ID, "owner", Batch{Sequence: i, Events: []Input{{Kind: "key", Key: 13}}}); e != nil {
			t.Fatal(e)
		}
	}
	if e := h.Input(ctx, q.ID, "owner", Batch{Sequence: 65, Events: []Input{{Kind: "key", Key: 13}}}); e == nil {
		t.Fatal("unbounded input queue")
	}
	*now = now.Add(2 * time.Second)
	r, e := h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "active"})
	if e != nil || len(r.Inputs) != 0 {
		t.Fatal("stale input replayed")
	}
	*now = now.Add(2 * time.Second)
	_, b, e := h.View(ctx, q.ID, "owner")
	if e != nil || len(b) != 0 {
		t.Fatal("stale frame displayed")
	}
	if _, e = h.Create(ctx, testDevice, "owner", "technician", true, 0, ""); !errors.Is(e, ErrUnavailable) {
		t.Fatal("concurrent device session")
	}
}
func TestAuditFailureCannotActivateOrRetainMedia(t *testing.T) {
	h, _, _, _ := testHub(t)
	ctx := context.Background()
	q := start(t, h, true)
	h.audit = func(context.Context, string, string, string, string, time.Time) error { return errors.New("offline") }
	if _, e := h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "active", Frame: testJPEG(t)}); e == nil {
		t.Fatal("audit failed open")
	}
	if len(h.sessions) != 0 {
		t.Fatal("media retained")
	}
	if _, e := h.Create(ctx, testDevice, "owner", "technician", true, 0, ""); e == nil {
		t.Fatal("request audit failed open")
	}
}
func TestConcurrentDesktopRequestsOnlyOneWins(t *testing.T) {
	h, _, _, _ := testHub(t)
	ctx := context.Background()
	_, _ = h.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer})
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, e := h.Create(ctx, testDevice, "owner", "technician", true, 0, ""); results <- e })
	}
	wg.Wait()
	close(results)
	wins := 0
	for e := range results {
		if e == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatal(wins)
	}
}
func TestProtocolRejectsOversizedMalformedAndUnknownFields(t *testing.T) {
	for _, b := range [][]byte{[]byte(`{"unknown":1}`), []byte(`{} {}`), bytes.Repeat([]byte{'x'}, MaxWire+1)} {
		var r Reply
		if Decode(b, &r) == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
	for _, v := range []Input{{Kind: "shell", Text: "whoami"}, {Kind: "key", Key: 91}, {Kind: "click", Button: 1, X: 65536}, {Kind: "text", Text: "x", Ctrl: true}, {Kind: "text", Text: string([]byte{0xff})}, {Kind: "move", Key: 13}, {Kind: "key", Key: 13, Text: "x"}} {
		if v.Valid() {
			t.Fatal("invalid input", v)
		}
	}
	var b bytes.Buffer
	_ = jpeg.Encode(&b, image.NewRGBA(image.Rect(0, 0, 1281, 1)), nil)
	if FrameValid(b.Bytes()) || FrameValid([]byte("not a JPEG")) || FrameValid(make([]byte, MaxFrame+1)) {
		t.Fatal("invalid frame")
	}
}
func FuzzProtocol(f *testing.F) {
	f.Add([]byte(`{"kind":"key","key":13}`))
	f.Add([]byte(`{"ready":true}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var i Input
		if Decode(b, &i) == nil {
			_ = i.Valid()
		}
		var p Exchange
		if Decode(b, &p) == nil {
			_ = p.Valid()
		}
	})
}

// Display and quality are chosen in the
// dashboard from what the companion reports, at start and during the
// session; a companion that reports no displays offers only display 0.
func TestDisplayChoice(t *testing.T) {
	ctx := context.Background()
	h := NewHub(func(context.Context, string, string, time.Time) error { return nil }, func(context.Context, string, string, string, string, time.Time) error { return nil })
	peer := strings.Repeat("e", 32)
	two := []Display{{Index: 0, Width: 1920, Height: 1080, Primary: true}, {Index: 1, Left: 1920, Width: 1280, Height: 1024}}
	if _, e := h.Exchange(ctx, "device", Exchange{Ready: true, Peer: peer, Displays: two}); e != nil {
		t.Fatal(e)
	}
	if d, ok, e := h.Displays(ctx, "device", "owner"); e != nil || !ok || len(d) != 2 {
		t.Fatal("displays", d, ok, e)
	}
	if _, e := h.Create(ctx, "device", "owner", "admin", false, 2, ""); e != ErrInvalid {
		t.Fatal("display outside the layout", e)
	}
	if _, e := h.Create(ctx, "device", "owner", "admin", false, 0, "best"); e != ErrInvalid {
		t.Fatal("unknown quality", e)
	}
	q, e := h.Create(ctx, "device", "owner", "admin", false, 1, "detail")
	if e != nil || q.Display != 1 || q.Quality != "detail" {
		t.Fatal("create", q, e)
	}
	if e = h.Configure(ctx, q.ID, "owner", 0, "bandwidth"); e != nil {
		t.Fatal(e)
	}
	if e = h.Configure(ctx, q.ID, "intruder", 0, "bandwidth"); e != ErrInvalid {
		t.Fatal("another owner configured the session", e)
	}
	r, e := h.Exchange(ctx, "device", Exchange{Ready: true, Peer: peer, Displays: two})
	if e != nil || r.Request == nil || r.Request.Display != 0 || r.Request.Quality != "bandwidth" {
		t.Fatal("change not sent to the companion", r.Request, e)
	}
	if v, _, e := h.View(ctx, q.ID, "owner"); e != nil || len(v.Displays) != 2 || v.Quality != "bandwidth" {
		t.Fatal("view", v, e)
	}
	_ = h.Stop(ctx, q.ID, "owner")
	// An older companion reports no displays: only its primary display.
	if _, e = h.Exchange(ctx, "old", Exchange{Ready: true, Peer: peer}); e != nil {
		t.Fatal(e)
	}
	if _, e = h.Create(ctx, "old", "owner", "admin", false, 1, ""); e != ErrInvalid {
		t.Fatal("second display on an old companion", e)
	}
	if _, e = h.Create(ctx, "old", "owner", "admin", false, 0, ""); e != nil {
		t.Fatal(e)
	}
	if DisplaysValid([]Display{{Index: 1, Width: 1, Height: 1, Primary: true}}) || DisplaysValid([]Display{{Index: 0, Width: 1, Height: 1}}) {
		t.Fatal("bad display lists accepted")
	}
}
