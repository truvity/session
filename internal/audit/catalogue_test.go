package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truvity/audit/emitter"

	"github.com/truvity/session/core"
	"github.com/truvity/session/internal/audit"
)

// The catalogue as a writer reads it: the one item, with the release, the policy, the table and the schemas.
type catalogueDoc map[string]struct {
	Release string `json:"release"`
	Policy  int    `json:"policy"`
	Table   struct {
		OCSF    string `json:"ocsf"`
		Product string `json:"product"`
		Actions []struct {
			Name       string `json:"name"`
			Actor      string `json:"actor"`
			Class      int    `json:"class"`
			Activities []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"activities"`
			Outcomes []string `json:"outcomes"`
			Subject  string   `json:"subject"`
			Policy   string   `json:"policy"`
			Fields   map[string]struct {
				Type     string `json:"type"`
				Required bool   `json:"required"`
			} `json:"fields"`
		} `json:"actions"`
	} `json:"table"`
	Schemas []struct {
		Name string `json:"name"`
		JSON string `json:"json"`
	} `json:"schemas"`
}

func TestTheCommittedCatalogueIsTheTables(t *testing.T) {
	want, err := audit.Catalogue(audit.CatalogueRelease)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(audit.CatalogueFile)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is not what the table makes: run `just catalogue` and commit it", audit.CatalogueFile)
	}
	again, err := audit.Catalogue(audit.CatalogueRelease)
	if err != nil || !bytes.Equal(again, want) {
		t.Fatal("the catalogue is not the same bytes twice")
	}
}

func TestTheCatalogueRefusesAReleaseThatIsNotAVersion(t *testing.T) {
	for _, r := range []string{"", "v0.1.0", "0.1", "latest"} {
		if _, err := audit.Catalogue(r); err == nil {
			t.Errorf("%q: made a catalogue", r)
		}
	}
	b, err := audit.Catalogue("1.2.3-rc.1")
	if err != nil {
		t.Fatal(err)
	}
	var doc catalogueDoc
	if err := json.Unmarshal(b, &doc); err != nil || doc["default"].Release != "1.2.3-rc.1" {
		t.Fatalf("release: %v %v", err, doc)
	}
}

// A writer that knows only the catalogue's bytes can check every record session makes: the table it rebuilds from the
// catalogue's rows and schemas accepts each action, and each record validates against the schema of its action.
func TestEveryRecordValidatesAgainstTheCatalogueAlone(t *testing.T) {
	b, err := audit.Catalogue(audit.CatalogueRelease)
	if err != nil {
		t.Fatal(err)
	}
	var doc catalogueDoc
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 1 {
		t.Fatalf("items: %d", len(doc))
	}
	it, ok := doc[audit.CatalogueItem]
	if !ok {
		t.Fatal("no item default")
	}
	if it.Policy != emitter.PolicyVersion || it.Table.OCSF != emitter.OCSFVersion || it.Table.Product != audit.Product {
		t.Fatalf("policy %d ocsf %q product %q", it.Policy, it.Table.OCSF, it.Table.Product)
	}
	files := map[string]string{}
	for _, s := range it.Schemas {
		files[s.Name] = s.JSON
	}
	if err := emitter.CheckPolicy(files); err != nil {
		t.Fatal(err)
	}
	var rows []emitter.Row
	for _, a := range it.Table.Actions {
		r := emitter.Row{Name: a.Name, Component: a.Actor, Class: a.Class}
		for _, act := range a.Activities {
			r.Activities = append(r.Activities, emitter.Activity{ID: act.ID, Name: act.Name})
		}
		for _, o := range a.Outcomes {
			r.Outcomes = append(r.Outcomes, map[string]emitter.Status{"success": emitter.StatusSuccess, "failure": emitter.StatusFailure}[o])
		}
		rows = append(rows, r)
		delete(files, a.Name+".schema.json")
	}
	delete(files, emitter.DefsName)
	if len(files) != 0 {
		t.Fatalf("schemas of no action: %v", files)
	}
	for _, s := range it.Schemas {
		files[s.Name] = s.JSON
	}
	table, err := emitter.NewTable(rows, files)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(table.Names(), " "); got != "back-channel-logout denied logout refresh sign-in token-exchange" {
		t.Fatalf("actions: %s", got)
	}

	a := newAuditor(t, &syncBuffer{}, nil)
	for _, e := range []core.Event{
		{Kind: core.EventSignIn, Subject: subject, Issuer: issuer},
		{Kind: core.EventSignInFailed, Issuer: issuer, Reason: "state"},
		{Kind: core.EventLogout, Subject: subject, Issuer: issuer},
		{Kind: core.EventBackChannelLogout, Issuer: issuer, Reason: "signature"},
		{Kind: core.EventDenied, Subject: subject, Issuer: issuer, Route: "/api/", Reason: "forbidden", PolicyDigest: digest},
		{Kind: core.EventExchange, Subject: subject, Issuer: issuer, Audience: "https://billing.example.com"},
		{Kind: core.EventRefreshFailed, Subject: subject, Issuer: issuer, Reason: "invalid_grant"},
	} {
		e.Site = "docs"
		rec, err := a.Record(context.Background(), e)
		if err != nil {
			t.Fatalf("%s: %v", e.Kind, err)
		}
		if err := table.Validate(rec); err != nil {
			t.Errorf("%s: the catalogue refuses the record: %v", e.Kind, err)
		}
	}
}
