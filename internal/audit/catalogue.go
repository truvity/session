package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/truvity/audit/emitter"
)

// CatalogueFile is the path, from the repository's root, of the committed catalogue (decision 0036): the payload of session's
// AuditCatalogue for the release CatalogueRelease. `just catalogue` writes it and CI fails while it differs from Catalogue.
const CatalogueFile = "deploy/audit/audit-catalogue.json"

// CatalogueRelease is the release of the committed catalogue. A writer refuses a record whose release is newer than the
// catalogue's, and every build before the first tag is a pre-release of 0.0.0 (0.0.0-dev, 0.0.0-master.<commit>), which 0.0.0
// covers. A tagged release's catalogue is `session catalogue --release X.Y.Z`: the same table with that release.
const CatalogueRelease = "0.0.0"

// CatalogueItem is the id of the catalogue's one item: the kind AuditCatalogue is a singleton for each project (audit record 0015).
const CatalogueItem = "default"

// The catalogue's item, in the parts of audit's reference ("Action table and catalogue", "Configuration kinds"): the release it
// covers, the version of the schema policy, the action table and the schema documents.
type catalogue struct {
	Release string          `json:"release"`
	Policy  int             `json:"policy"`
	Table   catalogueTable  `json:"table"`
	Schemas []catalogueFile `json:"schemas"`
}

// catalogueTable is session's action table in the keys of audit's table format.
type catalogueTable struct {
	OCSF    string           `json:"ocsf"`
	Product string           `json:"product"`
	Actions []catalogueEntry `json:"actions"`
}

type catalogueEntry struct {
	Name       string                    `json:"name"`
	Actor      string                    `json:"actor"`
	Class      int                       `json:"class"`
	Activities []catalogueActivity       `json:"activities"`
	Outcomes   []string                  `json:"outcomes"`
	Subject    string                    `json:"subject,omitempty"`
	Policy     string                    `json:"policy,omitempty"`
	Fields     map[string]catalogueField `json:"fields"`
}

type catalogueActivity struct {
	ID   int    `json:"id"`
	Name string `json:"name,omitempty"`
}

type catalogueField struct {
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
}

// catalogueFile is one schema document: its file name, which the documents reference one another by, and its JSON text, the
// bytes that the schema policy was checked on.
type catalogueFile struct {
	Name string `json:"name"`
	JSON string `json:"json"`
}

// Catalogue is the payload of session's signed AuditCatalogue document for release: the one item CatalogueItem, holding the
// release, the schema policy's version, the action table and its schemas, as indented JSON with a final newline. The same table
// always gives the same bytes. It fails unless release is a semantic version, the table loads with its schemas, and the schemas
// pass the emitter's schema policy, so that a catalogue that a writer would refuse at its start is never made.
func Catalogue(release string) ([]byte, error) {
	if !emitter.ValidRelease(release) {
		return nil, fmt.Errorf("audit: the release %q is not a semantic version", release)
	}
	if _, err := Table(); err != nil {
		return nil, err
	}
	files := Schemas()
	if err := emitter.CheckPolicy(files); err != nil {
		return nil, fmt.Errorf("audit: the schemas fail the schema policy: %w", err)
	}
	c := catalogue{Release: release, Policy: emitter.PolicyVersion,
		Table: catalogueTable{OCSF: emitter.OCSFVersion, Product: Product}}
	for _, r := range rows {
		c.Table.Actions = append(c.Table.Actions, r.entry())
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		c.Schemas = append(c.Schemas, catalogueFile{Name: name, JSON: files[name]})
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]catalogue{CatalogueItem: c}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// entry is the row in the keys of audit's table format.
func (r row) entry() catalogueEntry {
	e := catalogueEntry{Name: r.Name, Actor: r.Component, Class: r.Class, Fields: map[string]catalogueField{}}
	for _, a := range r.Activities {
		e.Activities = append(e.Activities, catalogueActivity{ID: a.ID, Name: a.Name})
	}
	for _, o := range r.Outcomes {
		e.Outcomes = append(e.Outcomes, outcomeName(o))
	}
	switch r.subject {
	case optional:
		e.Subject = "optional"
	case required:
		e.Subject = "required"
	}
	if r.policy {
		e.Policy = "optional"
	}
	for f, need := range r.fields {
		e.Fields[f] = catalogueField{Type: "text", Required: need}
	}
	return e
}

func outcomeName(s emitter.Status) string {
	if s == emitter.StatusSuccess {
		return "success"
	}
	return "failure"
}
