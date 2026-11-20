// Package status keeps the log and the status file the manager reads.
package status

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Tracker struct {
	mu        sync.Mutex
	path      string
	live      bool
	since     time.Time
	peer      string
	sessions  int
	transport string
	rx, tx    atomic.Uint64
	loss      atomic.Int32 // percent of keepalives lost, -1 = not measured
}

// Setup sends log output to stdout and the log file.
func Setup(logFile string) {
	log.SetFlags(log.LstdFlags)
	if logFile == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(logFile), 0o755)
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("log file: %v", err)
		return
	}
	log.SetOutput(io.MultiWriter(os.Stdout, f))
}

func New(path, transport string) *Tracker {
	t := &Tracker{path: path, since: time.Now(), transport: transport}
	t.loss.Store(-1)
	if path != "" {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
	}
	t.write()
	go func() {
		for range time.Tick(5 * time.Second) {
			t.write()
		}
	}()
	return t
}

// Set records the link state and logs transitions with fixed phrases.
func (t *Tracker) Set(live bool, sessions int, peer string) {
	t.mu.Lock()
	changed := live != t.live
	t.live, t.sessions = live, sessions
	if peer != "" {
		t.peer = peer
	}
	if changed {
		t.since = time.Now()
	}
	t.mu.Unlock()
	if changed {
		if live {
			log.Printf("peer %s - tunnel is live", peer)
		} else {
			log.Printf("TUNNEL IS DOWN")
		}
		t.write()
	}
}

// SetLoss records the share of the peer's keepalives that never arrived.
func (t *Tracker) SetLoss(pct int) {
	prev := t.loss.Swap(int32(pct))
	if pct >= 30 && prev < 30 {
		log.Printf("link is lossy: %d%% of keepalives lost - this route may filter or rate limit this protocol", pct)
	} else if pct < 30 && prev >= 30 {
		log.Printf("link loss back to %d%%", pct)
	}
}

func (t *Tracker) AddRx(n int) {
	if t != nil {
		t.rx.Add(uint64(n))
	}
}

func (t *Tracker) AddTx(n int) {
	if t != nil {
		t.tx.Add(uint64(n))
	}
}

func (t *Tracker) write() {
	if t.path == "" {
		return
	}
	t.mu.Lock()
	st := "connecting"
	if t.live {
		st = "connected"
	}
	m := map[string]any{
		"state":     st,
		"since":     t.since.Unix(),
		"peer":      t.peer,
		"sessions":  t.sessions,
		"transport": t.transport,
		"rx":        t.rx.Load(),
		"tx":        t.tx.Load(),
		"loss":      t.loss.Load(),
		"updated":   time.Now().Unix(),
		"pid":       os.Getpid(),
	}
	t.mu.Unlock()
	b, _ := json.Marshal(m)
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err == nil {
		_ = os.Rename(tmp, t.path)
	}
}

func Human(n uint64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if f < 1024 {
			return fmt.Sprintf("%.1f%s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1fPB", f)
}
