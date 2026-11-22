package policy

import (
	"context"

	"connectrpc.com/connect"

	sourcev1 "github.com/truvity/atoom/source/gen/atoom/source/v1alpha1"
	"github.com/truvity/atoom/source/gen/atoom/source/v1alpha1/sourcev1alpha1connect"
)

// SourceLoader reads the bundle through atoom's source port: the document Name (source/file serves it from <Name>.jws). The
// document is Cedar policy text until atoom defines the signed bundle.
type SourceLoader struct {
	Source sourcev1alpha1connect.SourceServiceClient
	Name   string
}

// Load reads the document.
func (l SourceLoader) Load(ctx context.Context) (Bundle, error) {
	res, err := l.Source.Read(ctx, connect.NewRequest(&sourcev1.ReadRequest{Name: l.Name}))
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Name: l.Name, Policies: res.Msg.GetData()}, nil
}

// Static is a bundle held in memory (tests and examples).
type Static Bundle

// Load returns the bundle.
func (s Static) Load(context.Context) (Bundle, error) { return Bundle(s), nil }
