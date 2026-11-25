package audit

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/truvity/audit/emitter"
)

// Product is session's name in every record: metadata.product.name and the product object unmapped.session.
const Product = "session"

// Component is the emitting component: actor.user.uid is session@<scope>.
const Component = "session"

// The actions of session's table (metadata.event_code). sign-in-failed is the failure of sign-in, and refresh-failed the failure
// of refresh: an OCSF record says its outcome in status_id.
const (
	ActionSignIn            = "sign-in"
	ActionLogout            = "logout"
	ActionBackChannelLogout = "back-channel-logout"
	ActionDenied            = "denied"
	ActionTokenExchange     = "token-exchange"
	ActionRefresh           = "refresh"
)

// The OCSF 1.9.0 classes and activities of the table, by audit's class mapping ("Action table and catalogue").
const (
	classAuthentication = 3002 // Authentication
	classAPIActivity    = 6003 // API Activity
	activityLogon       = 1
	activityLogoff      = 2
	activityOther       = 99
)

// The members of the product object, unmapped.session: the facts of session's events that OCSF has no attribute for. Each is a
// name or an address session holds, never a value a request carried.
const (
	fieldSite     = "site"     // the site of the event
	fieldIssuer   = "issuer"   // the issuer of the session or of the sign-in
	fieldRoute    = "route"    // the route a denial refused: its name, by default its match
	fieldAudience = "audience" // the API audience of a token exchange
)

// row is one action of session's table: the emitter's row and what the generated schema holds the record to.
type row struct {
	emitter.Row
	// subject says the record names a person: always (required), maybe (optional) or never.
	subject presence
	// policy says the record may carry the policy decision that gated it.
	policy bool
	// fields are the members of the product object and whether every record of the action carries them.
	fields map[string]bool
}

type presence int

const (
	never presence = iota
	optional
	required
)

var (
	success = emitter.StatusSuccess
	failure = emitter.StatusFailure
)

// rows is session's action table (decision 0023): one row for each kind of core.Event, a kind and its failure folded into one
// action.
var rows = []row{
	{Row: emitter.Row{Name: ActionSignIn, Component: Component, Class: classAuthentication,
		Activities: []emitter.Activity{{ID: activityLogon}}, Outcomes: []emitter.Status{success, failure}},
		subject: optional, fields: map[string]bool{fieldSite: true, fieldIssuer: false}},
	{Row: emitter.Row{Name: ActionLogout, Component: Component, Class: classAuthentication,
		Activities: []emitter.Activity{{ID: activityLogoff}}, Outcomes: []emitter.Status{success}},
		subject: required, fields: map[string]bool{fieldSite: true, fieldIssuer: false}},
	{Row: emitter.Row{Name: ActionBackChannelLogout, Component: Component, Class: classAuthentication,
		Activities: []emitter.Activity{{ID: activityLogoff}}, Outcomes: []emitter.Status{success, failure}},
		subject: optional, fields: map[string]bool{fieldSite: true, fieldIssuer: false}},
	{Row: emitter.Row{Name: ActionDenied, Component: Component, Class: classAPIActivity,
		Activities: []emitter.Activity{{ID: activityOther, Name: "Check"}}, Outcomes: []emitter.Status{failure}},
		subject: optional, policy: true, fields: map[string]bool{fieldSite: true, fieldIssuer: false, fieldRoute: false}},
	{Row: emitter.Row{Name: ActionTokenExchange, Component: Component, Class: classAuthentication,
		Activities: []emitter.Activity{{ID: activityOther, Name: "Token Exchange"}}, Outcomes: []emitter.Status{success, failure}},
		subject: required, fields: map[string]bool{fieldSite: true, fieldIssuer: false, fieldAudience: true}},
	{Row: emitter.Row{Name: ActionRefresh, Component: Component, Class: classAuthentication,
		Activities: []emitter.Activity{{ID: activityOther, Name: "Refresh"}}, Outcomes: []emitter.Status{failure}},
		subject: required, fields: map[string]bool{fieldSite: true, fieldIssuer: false}},
}

// defs are the shared definitions: the value types of audit's table format that session uses, and the note of lost facts.
var defs = map[string]any{
	// text is bounded text; the emitter refuses an e-mail shape in any string.
	"text": map[string]any{"type": "string", "minLength": 1, "maxLength": emitter.StringMax},
	// reason is a status_code: the closed reason of a refusal, a rule and never a value.
	"reason": map[string]any{"type": "string", "pattern": `^[A-Za-z][A-Za-z0-9_.:\-]{0,63}$`},
	// pseudonym is a subject as audit writes it (audit record 0011); unknown is an Authentication's subject that was not named.
	"user_uid":  map[string]any{"type": "string", "pattern": `^(unknown|p1\.[0-9]{6}\.[A-Za-z0-9_\-]{22})$`},
	"pseudonym": map[string]any{"type": "string", "pattern": `^p1\.[0-9]{6}\.[A-Za-z0-9_\-]{22}$`},
	// hex96 is a SHA-384 digest: the digest of the policy set.
	"hex96": map[string]any{"type": "string", "pattern": `^[0-9a-f]{96}$`},
	"lost": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"process", "since", "total"},
		"properties": map[string]any{
			"process": map[string]any{"type": "string", "pattern": `^[0-9a-f]{16}$`},
			"since":   map[string]any{"type": "integer", "minimum": 0, "maximum": maxSafe},
			"total":   map[string]any{"type": "integer", "minimum": 1, "maximum": maxSafe},
		}},
}

const (
	draft2020 = "https://json-schema.org/draft/2020-12/schema"
	maxSafe   = 1<<53 - 1
)

func ref(name string) map[string]any {
	return map[string]any{"$ref": emitter.DefsName + "#/$defs/" + name}
}

// schema is the JSON Schema of the records of one row: the action, its class, activities and outcomes, the product, the subject
// as a pseudonym, the policy and a closed product object. The members the emitter fills from its configuration and the class
// (actor, metadata.uid, time, api, src_endpoint, service) are its own and left open here.
func (r row) schema() map[string]any {
	activities, outcomes := []any{}, []any{}
	for _, a := range r.Activities {
		activities = append(activities, a.ID)
	}
	for _, o := range r.Outcomes {
		outcomes = append(outcomes, int(o))
	}
	object := map[string]any{"lost": ref("lost")}
	need := []string{}
	for _, f := range slices.Sorted(maps.Keys(r.fields)) {
		object[f] = ref("text")
		if r.fields[f] {
			need = append(need, f)
		}
	}
	props := map[string]any{
		"metadata": map[string]any{"type": "object", "required": []string{"event_code", "product"}, "properties": map[string]any{
			"event_code": map[string]any{"const": r.Name},
			"product": map[string]any{"type": "object", "required": []string{"name", "version"}, "properties": map[string]any{
				"name": map[string]any{"const": Product}, "version": ref("text"),
			}},
		}},
		"class_uid":   map[string]any{"const": r.Class},
		"activity_id": map[string]any{"enum": activities},
		"status_id":   map[string]any{"enum": outcomes},
		"status_code": ref("reason"),
		"unmapped": map[string]any{"type": "object", "additionalProperties": false, "required": []string{Product},
			"properties": map[string]any{Product: map[string]any{
				"type": "object", "additionalProperties": false, "required": need, "properties": object,
			}}},
	}
	top := []string{"metadata", "class_uid", "activity_id", "status_id", "unmapped"}
	switch {
	case r.Class == classAuthentication:
		// OCSF requires the user of an Authentication: a pseudonym, or unknown when none could be named.
		props["user"] = map[string]any{"type": "object", "required": []string{"uid"}, "properties": map[string]any{"uid": ref("user_uid")}}
		top = append(top, "user")
	case r.subject != never:
		// API Activity has no user: the person is the resource of the call.
		props["resources"] = map[string]any{"type": "array", "maxItems": 1, "items": map[string]any{
			"type": "object", "required": []string{"type", "uid"},
			"properties": map[string]any{"type": map[string]any{"const": "person"}, "uid": ref("pseudonym")},
		}}
	}
	if r.policy {
		props["policy"] = map[string]any{"type": "object", "required": []string{"uid"}, "properties": map[string]any{
			"uid": ref("text"), "version": ref("hex96"),
		}}
	}
	return map[string]any{"$schema": draft2020, "title": Product + " " + r.Name, "type": "object", "required": top, "properties": props}
}

// Schemas are the schema documents of session's table, by file name: the shared definitions and one document for each action.
// The catalogue of an installation is the table with these documents.
func Schemas() map[string]string {
	out := map[string]string{DefsFile: mustJSON(map[string]any{"$schema": draft2020, "$defs": defs})}
	for _, r := range rows {
		out[r.Name+".schema.json"] = mustJSON(r.schema())
	}
	return out
}

// DefsFile is the name of the document of shared definitions.
const DefsFile = emitter.DefsName

// Table is session's action table with its schemas, for the emitter.
func Table() (*emitter.Table, error) {
	rs := make([]emitter.Row, 0, len(rows))
	for _, r := range rows {
		rs = append(rs, r.Row)
	}
	return emitter.NewTable(rs, Schemas())
}

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err) // the documents are maps of strings, numbers and lists: they always encode
	}
	return string(b) + "\n"
}

func rowOf(name string) row {
	for _, r := range rows {
		if r.Name == name {
			return r
		}
	}
	panic("audit: no row " + name)
}
