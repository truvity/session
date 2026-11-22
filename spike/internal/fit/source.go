package fit

import (
	"connectrpc.com/connect"

	"github.com/truvity/atoom/common/call"
	"github.com/truvity/atoom/source/file"
	"github.com/truvity/atoom/source/gen/atoom/source/v1alpha1/sourcev1alpha1connect"
)

// NewSource mounts the Go source/file driver over dir in-process and returns the generated client.
func NewSource(dir string, opts ...connect.HandlerOption) (sourcev1alpha1connect.SourceServiceClient, func(), error) {
	d, err := file.Open(dir)
	if err != nil {
		return nil, nil, err
	}
	svc, err := file.New(file.Options{Dir: d})
	if err != nil {
		return nil, nil, err
	}
	path, h := svc.Handler(opts...)
	hc, stop := Mount(path, h)
	return sourcev1alpha1connect.NewSourceServiceClient(hc, "http://source", call.ClientOptions()...), func() { stop(); _ = d.Close() }, nil
}
