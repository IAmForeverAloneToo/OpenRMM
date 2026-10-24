package desktop

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/jpeg"
	"math/rand/v2"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Exercise the production framing and agent bridge with a large private image.
// A synthetic endpoint replaces HTTP; no real desktop/consent is involved.
func TestLargeFrameOverLocalPipe(t *testing.T) {
	if !consoleUser() {
		t.Skip("requires a console-session test process")
	}
	id, e := RandomID()
	if e != nil {
		t.Fatal(e)
	}
	path, _ := windows.UTF16PtrFromString(`\\.\pipe\OpenRMM.Desktop.Test.` + id)
	h, e := windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_NOWAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	received := make(chan int, 1)
	finished := make(chan error, 1)
	q := Request{ID: testDevice, Actor: "test", Control: true, Expires: time.Now().Add(15 * time.Minute).Unix()}
	go func() {
		for ctx.Err() == nil {
			e := windows.ConnectNamedPipe(h, nil)
			if e == nil || errors.Is(e, windows.ERROR_PIPE_CONNECTED) {
				break
			}
			if !errors.Is(e, windows.ERROR_PIPE_LISTENING) {
				finished <- e
				return
			}
			if e = pipeWait(ctx); e != nil {
				finished <- e
				return
			}
		}
		finished <- serveCompanion(ctx, h, testPeer, func(_ context.Context, p Exchange) (Reply, error) {
			if p.State == "active" {
				received <- len(p.Frame)
			}
			return Reply{Request: &q}, nil
		})
	}()
	client, e := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(client)
	mode := uint32(windows.PIPE_NOWAIT)
	if e = windows.SetNamedPipeHandleState(client, &mode, nil, nil); e != nil {
		t.Fatal(e)
	}
	var r Reply
	if e = pipeWrite(ctx, client, Exchange{}); e != nil {
		t.Fatal(e)
	}
	if e = pipeRead(ctx, client, &r); e != nil {
		t.Fatal(e)
	}
	img := image.NewRGBA(image.Rect(0, 0, 1280, 720))
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range img.Pix {
		img.Pix[i] = byte(rng.Uint32())
	}
	var b bytes.Buffer
	if e = jpeg.Encode(&b, img, &jpeg.Options{Quality: 85}); e != nil {
		t.Fatal(e)
	}
	if b.Len() < 65536 || !FrameValid(b.Bytes()) {
		t.Fatal("inadequate image fixture", b.Len())
	}
	frame := make([]byte, MaxFrame)
	copy(frame, b.Bytes()) // valid JPEG followed by padding, at the maximum size
	if e = pipeWrite(ctx, client, Exchange{ID: q.ID, State: "active", Frame: frame}); e != nil {
		select {
		case cause := <-finished:
			t.Fatal("large-frame write", e, "server cause", cause)
		default:
			t.Fatal("large-frame write", e)
		}
	}
	if e = pipeRead(ctx, client, &r); e != nil {
		select {
		case cause := <-finished:
			t.Fatal("large-frame read", e, "server cause", cause)
		default:
			t.Fatal("large-frame read", e)
		}
	}
	select {
	case n := <-received:
		if n != len(frame) {
			t.Fatal("truncated frame")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("bridge did not stop")
	}
}
