package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// mockFeed simule un serveur HTTP qui retourne une liste d'IPs
func mockServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}))
}

func newTestFeed(t *testing.T) *Feed {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return NewFeed(logger)
}

func TestIsMalicious_KnownIP(t *testing.T) {
	feed := newTestFeed(t)
	srv := mockServer(t, "# comment\n1.2.3.4\n5.6.7.8\n")
	defer srv.Close()

	// Override sources pour le test
	count, err := feed.fetchSource(context.Background(), srv.URL, "#", feed.ips)
	if err != nil {
		t.Fatalf("fetchSource: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 IPs, got %d", count)
	}
	if !feed.IsMalicious("1.2.3.4") {
		t.Error("1.2.3.4 should be malicious")
	}
	if !feed.IsMalicious("5.6.7.8") {
		t.Error("5.6.7.8 should be malicious")
	}
}

func TestIsMalicious_UnknownIP(t *testing.T) {
	feed := newTestFeed(t)
	srv := mockServer(t, "1.2.3.4\n")
	defer srv.Close()

	feed.fetchSource(context.Background(), srv.URL, "#", feed.ips)

	if feed.IsMalicious("9.9.9.9") {
		t.Error("9.9.9.9 should not be malicious")
	}
}

func TestFetchSource_IgnoresComments(t *testing.T) {
	feed := newTestFeed(t)
	srv := mockServer(t, "# this is a comment\n\n1.1.1.1\n# another comment\n2.2.2.2\n")
	defer srv.Close()

	count, err := feed.fetchSource(context.Background(), srv.URL, "#", feed.ips)
	if err != nil {
		t.Fatalf("fetchSource: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 IPs, got %d", count)
	}
}

func TestFetchSource_HTTPError(t *testing.T) {
	feed := newTestFeed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := feed.fetchSource(context.Background(), srv.URL, "#", feed.ips)
	if err == nil {
		t.Error("expected error on HTTP 500, got nil")
	}
}

func TestCount(t *testing.T) {
	feed := newTestFeed(t)
	srv := mockServer(t, "1.1.1.1\n2.2.2.2\n3.3.3.3\n")
	defer srv.Close()

	feed.fetchSource(context.Background(), srv.URL, "#", feed.ips)

	if feed.Count() != 3 {
		t.Errorf("expected count 3, got %d", feed.Count())
	}
}
