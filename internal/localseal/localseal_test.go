package localseal_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/truvity/session/internal/localseal"
)

func TestSealOpenMac(t *testing.T) {
	ctx := context.Background()
	s, err := localseal.New(localseal.NewRoot(), []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal(ctx, "a", []byte("addr-1"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("the plaintext is visible")
	}
	if got, err := s.Open(ctx, "a", []byte("addr-1"), sealed); err != nil || string(got) != "secret" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := s.Open(ctx, "a", []byte("addr-2"), sealed); err == nil {
		t.Fatal("a value opened under another address")
	}
	if _, err := s.Open(ctx, "b", []byte("addr-1"), sealed); err == nil {
		t.Fatal("a value opened under another purpose")
	}
	if _, err := s.Seal(ctx, "c", nil, nil); err == nil {
		t.Fatal("an undeclared purpose sealed")
	}
	ma, _ := s.Mac(ctx, "a", []byte("x"))
	mb, _ := s.Mac(ctx, "b", []byte("x"))
	ma2, _ := s.Mac(ctx, "a", []byte("x"))
	if bytes.Equal(ma, mb) || !bytes.Equal(ma, ma2) || len(ma) != 32 {
		t.Fatal("the MAC is not per purpose and stable")
	}
	other, _ := localseal.New(localseal.NewRoot(), []string{"a"})
	if _, err := other.Open(ctx, "a", []byte("addr-1"), sealed); err == nil {
		t.Fatal("a value opened under another root")
	}
}

func TestReadRoot(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "root")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(localseal.NewRoot())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := localseal.ReadRoot(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil { //nolint:gosec // G302: the test makes a too-open file on purpose
		t.Fatal(err)
	}
	if _, err := localseal.ReadRoot(p); err == nil {
		t.Fatal("a group-readable root was accepted")
	}
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte("abcd"), 0o600)
	if _, err := localseal.ReadRoot(short); err == nil {
		t.Fatal("a short root was accepted")
	}
}
