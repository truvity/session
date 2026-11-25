// Package core is the session core, the block of decision record 0009: the session records, the opaque cookie, idle and
// absolute expiry, the index entries and tombstones of back-channel logout, and the check that answers "may this request pass?".
//
// Its dependencies are passed in: atoom's store port as its generated ConnectRPC client (decision 0006), a Sealer that stands
// for atoom's seal block until that block exists, a Policy (Cedar, decision 0007) and an Auditor (decision 0008). The core
// has no port interface of its own and never talks to a backend.
//
// The rules are session's own (decision 0004): the cookie, the paths, the lifetimes and the fail-closed answer.
//
// Store layout. Every key is a keyed hash, so nothing a browser holds and nothing that names a person is a key in clear:
//
//	s/<mac(session-key, id)>               the session item: a readable header and the sealed record; expires at the maximum lifetime.
//	                                       Its index entries sid = mac(lookup-key, iss, sid) and sub = mac(lookup-key, iss, sub) find
//	                                       it at a back-channel logout (decision 0031)
//	t/sid/..., t/sub/...                   the tombstones of back-channel logouts, in milliseconds
//	x/<mac(lookup-key, state)>             a sign-in transaction, sealed, used once
//	o/<mac(lookup-key, name)>              a name claimed once (the jti of a logout token)
package core
