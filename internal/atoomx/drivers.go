package atoomx

import (
	"github.com/truvity/atoom/common/call"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/purpose"
	"github.com/truvity/atoom/key/software"
	"github.com/truvity/atoom/source/file"
	"github.com/truvity/atoom/source/gen/atoom/source/v1alpha1/sourcev1alpha1connect"
	storedyn "github.com/truvity/atoom/store/dynamodb"
	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"
)

// Store is a mounted store driver and its client.
type Store struct {
	Items storev1alpha1connect.ItemServiceClient
	Stop  func()
}

// DynamoDB mounts atoom's store/dynamodb driver over the given DynamoDB client and table.
func DynamoDB(api storedyn.API, table string) (*Store, error) {
	svc, err := storedyn.New(storedyn.Options{DynamoDB: api, Table: table})
	if err != nil {
		return nil, err
	}
	path, h := svc.Handler()
	hc, stop := Mount(path, h)
	return &Store{Items: storev1alpha1connect.NewItemServiceClient(hc, "http://store", call.ClientOptions()...), Stop: stop}, nil
}

// Keys is a mounted key driver and its client.
type Keys struct {
	Keys keyv1alpha1connect.KeyStoreServiceClient
	Stop func()
}

// SoftwareKeys mounts atoom's key/software driver over a state directory, with the purposes session declares. environment names
// the installation for the driver's journal (development, staging or production).
func SoftwareKeys(stateDir string, purposes []purpose.Declaration, environment string) (*Keys, error) {
	svc, err := software.New(software.Options{StateDir: stateDir, Purposes: purposes, Environment: environment})
	if err != nil {
		return nil, err
	}
	path, h := svc.Handler()
	hc, stop := Mount(path, h)
	return &Keys{Keys: keyv1alpha1connect.NewKeyStoreServiceClient(hc, "http://key", call.ClientOptions()...), Stop: stop}, nil
}

// Source is a mounted source driver and its client.
type Source struct {
	Source sourcev1alpha1connect.SourceServiceClient
	Stop   func()
}

// FileSource mounts atoom's Go source/file driver over a directory of documents (<name>.jws).
func FileSource(dir string) (*Source, error) {
	d, err := file.Open(dir)
	if err != nil {
		return nil, err
	}
	svc, err := file.New(file.Options{Dir: d})
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	path, h := svc.Handler()
	hc, stop := Mount(path, h)
	return &Source{Source: sourcev1alpha1connect.NewSourceServiceClient(hc, "http://source", call.ClientOptions()...),
		Stop: func() { stop(); _ = d.Close() }}, nil
}
