package core

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

// Metrics counts what the check answers. Allowed requests are counted here and never logged one by one or emitted as an
// event (decision 0008). The counters carry no subject, path or header value.
type Metrics struct {
	mu           sync.Mutex
	checks       map[string]*atomic.Int64 // by outcome and reason, "allow", "deny/login_required", "unavailable/store", ...
	auditDropped atomic.Int64
	touchFailed  atomic.Int64
	// cacheWriteFailed counts tokens that were exchanged but could not be cached: the check used them, the next one exchanges again.
	cacheWriteFailed atomic.Int64
	// revocationFailed counts refresh tokens a logout could not revoke at the issuer (decision 0031): the logout went on.
	revocationFailed atomic.Int64
}

// NewMetrics returns zeroed counters.
func NewMetrics() *Metrics { return &Metrics{checks: map[string]*atomic.Int64{}} }

func (m *Metrics) count(label string) {
	m.mu.Lock()
	n, ok := m.checks[label]
	if !ok {
		n = &atomic.Int64{}
		m.checks[label] = n
	}
	m.mu.Unlock()
	n.Add(1)
}

// Checks returns the count of one outcome label ("allow", "deny/csrf", ...).
func (m *Metrics) Checks(label string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.checks[label]; ok {
		return n.Load()
	}
	return 0
}

// CountRevocationFailed counts a refresh token that a logout could not revoke at the issuer.
func (m *Metrics) CountRevocationFailed() { m.revocationFailed.Add(1) }

// RevocationsFailed is the number of refresh tokens that logouts could not revoke.
func (m *Metrics) RevocationsFailed() int64 { return m.revocationFailed.Load() }

// AuditDropped is the number of security-audit events the Auditor refused.
func (m *Metrics) AuditDropped() int64 { return m.auditDropped.Load() }

// WritePrometheus writes the counters in the Prometheus text format.
func (m *Metrics) WritePrometheus(w io.Writer, site string) error {
	m.mu.Lock()
	labels := make([]string, 0, len(m.checks))
	for l := range m.checks {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	vals := make([]int64, len(labels))
	for i, l := range labels {
		vals[i] = m.checks[l].Load()
	}
	m.mu.Unlock()
	if _, err := fmt.Fprintf(w, "# TYPE session_checks_total counter\n"); err != nil {
		return err
	}
	for i, l := range labels {
		outcome, reason := l, ""
		for j := 0; j < len(l); j++ {
			if l[j] == '/' {
				outcome, reason = l[:j], l[j+1:]
				break
			}
		}
		if _, err := fmt.Fprintf(w, "session_checks_total{site=%q,outcome=%q,reason=%q} %d\n", site, outcome, reason, vals[i]); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "# TYPE session_audit_dropped_total counter\nsession_audit_dropped_total{site=%q} %d\n"+
		"# TYPE session_idle_refresh_failed_total counter\nsession_idle_refresh_failed_total{site=%q} %d\n"+
		"# TYPE session_exchange_cache_write_failed_total counter\nsession_exchange_cache_write_failed_total{site=%q} %d\n"+
		"# TYPE session_logout_revocation_failed_total counter\nsession_logout_revocation_failed_total{site=%q} %d\n",
		site, m.auditDropped.Load(), site, m.touchFailed.Load(), site, m.cacheWriteFailed.Load(), site, m.revocationFailed.Load())
	return err
}
