package atoomx

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/truvity/atoom/common/call"
	"github.com/truvity/atoom/key/awskms"
	"github.com/truvity/atoom/key/gen/atoom/key/v1alpha1/keyv1alpha1connect"
	"github.com/truvity/atoom/key/purpose"
)

// The key drivers session can run for a purpose (design section 9, decision 0019). Which one holds each purpose is a start-up
// setting, not part of the site file.
const (
	// DriverSoftware is atoom's key/software: a key file in a state directory. For local runs and tests, and for installs that
	// accept a key on disk.
	DriverSoftware = "software"
	// DriverAWSKMS is atoom's key/awskms: a key that lives in AWS KMS and never leaves it.
	DriverAWSKMS = "awskms"
)

// KeyChoice is the driver of one purpose and, on AWS KMS, the key the deployment names for it.
type KeyChoice struct {
	Driver string
	// Key is the KMS key of the purpose: a key ID, a key ARN or an alias name (alias/...). Empty finds the key by the alias
	// alias/<prefix>/<purpose>. Always empty for the software driver.
	Key string
}

// ParseKeyChoices reads the values of --key, each PURPOSE=DRIVER or PURPOSE=awskms:KEY, against the declared purposes. A purpose
// that no value names is on the software driver. A purpose named twice, a purpose not declared, a driver session does not know
// and a key for the software driver are refused.
func ParseKeyChoices(values []string, declared []purpose.Declaration) (map[string]KeyChoice, error) {
	out := make(map[string]KeyChoice, len(declared))
	for _, d := range declared {
		out[d.Name] = KeyChoice{Driver: DriverSoftware}
	}
	seen := map[string]bool{}
	for _, v := range values {
		name, spec, ok := strings.Cut(v, "=")
		if !ok || name == "" || spec == "" {
			return nil, fmt.Errorf("--key %q: want PURPOSE=DRIVER or PURPOSE=awskms:KEY", v)
		}
		if _, declaredHere := out[name]; !declaredHere {
			return nil, fmt.Errorf("--key %q: session has no key purpose %q (it has %s)", v, name, strings.Join(names(declared), ", "))
		}
		if seen[name] {
			return nil, fmt.Errorf("--key %q: the purpose %q is named twice", v, name)
		}
		seen[name] = true
		driver, key, _ := strings.Cut(spec, ":")
		switch driver {
		case DriverSoftware:
			if key != "" {
				return nil, fmt.Errorf("--key %q: the software driver takes no key (its keys are in --key-dir)", v)
			}
		case DriverAWSKMS:
			if strings.Contains(spec, ":") && key == "" {
				return nil, fmt.Errorf("--key %q: an empty KMS key", v)
			}
		default:
			return nil, fmt.Errorf("--key %q: unknown key driver %q (software or awskms)", v, driver)
		}
		out[name] = KeyChoice{Driver: driver, Key: key}
	}
	return out, nil
}

func names(declared []purpose.Declaration) []string {
	out := make([]string, 0, len(declared))
	for _, d := range declared {
		out = append(out, d.Name)
	}
	return out
}

// KeyOptions are what OpenKeys needs.
type KeyOptions struct {
	// Purposes are the purposes session declares; Choices says which driver holds each (ParseKeyChoices).
	Purposes []purpose.Declaration
	Choices  map[string]KeyChoice
	// StateDir and Environment are the software driver's, when a purpose is on it.
	StateDir, Environment string
	// KMS returns the KMS client, when a purpose is on AWS KMS. It is called once, and only then, so an install without AWS needs
	// no AWS configuration.
	KMS func() (awskms.API, error)
	// AliasPrefix is the prefix of the aliases of the purposes on AWS KMS that name no key: alias/<AliasPrefix>/<purpose>.
	AliasPrefix string
}

// KeySet is the mounted key drivers and the client of each purpose's driver.
type KeySet struct {
	clients map[string]keyv1alpha1connect.KeyStoreServiceClient
	drivers map[string]string
	stops   []func()
}

// For returns the client of the driver that holds the purpose.
func (k *KeySet) For(name string) keyv1alpha1connect.KeyStoreServiceClient { return k.clients[name] }

// Driver names the driver that holds the purpose.
func (k *KeySet) Driver(name string) string { return k.drivers[name] }

// Stop stops the mounted drivers.
func (k *KeySet) Stop() {
	for _, s := range slices.Backward(k.stops) {
		s()
	}
}

// OpenKeys mounts one driver of each kind that holds a purpose, each declared only the purposes it holds, so a driver refuses
// the others. The KMS driver never makes a key (CreateKeys off): the deployment makes the keys and holds their key policy, and the
// role of session needs kms:DescribeKey, kms:GetPublicKey and kms:Sign only. Nothing is called here; Ensure of each purpose
// (signin.Signer.Ensure) finds its key at start.
func OpenKeys(o KeyOptions) (*KeySet, error) {
	ks := &KeySet{clients: map[string]keyv1alpha1connect.KeyStoreServiceClient{}, drivers: map[string]string{}}
	ok := false
	defer func() {
		if !ok {
			ks.Stop()
		}
	}()
	byDriver := map[string][]purpose.Declaration{}
	kmsKeys := map[string]string{}
	for _, d := range o.Purposes {
		c, has := o.Choices[d.Name]
		if !has {
			c = KeyChoice{Driver: DriverSoftware}
		}
		if c.Driver != DriverSoftware && c.Driver != DriverAWSKMS {
			return nil, fmt.Errorf("atoomx: unknown key driver %q", c.Driver)
		}
		byDriver[c.Driver] = append(byDriver[c.Driver], d)
		ks.drivers[d.Name] = c.Driver
		if c.Driver == DriverAWSKMS && c.Key != "" {
			kmsKeys[d.Name] = c.Key
		}
	}
	if ds := byDriver[DriverSoftware]; len(ds) > 0 {
		if o.StateDir == "" {
			return nil, fmt.Errorf("--key-dir is required: the purposes %s are on the software key driver", strings.Join(names(ds), ", "))
		}
		k, err := SoftwareKeys(o.StateDir, ds, o.Environment)
		if err != nil {
			return nil, err
		}
		ks.stops = append(ks.stops, k.Stop)
		for _, d := range ds {
			ks.clients[d.Name] = k.Keys
		}
	}
	if ds := byDriver[DriverAWSKMS]; len(ds) > 0 {
		if o.KMS == nil {
			return nil, errors.New("atoomx: a purpose is on AWS KMS and there is no KMS client")
		}
		api, err := o.KMS()
		if err != nil {
			return nil, fmt.Errorf("aws kms: %w", err)
		}
		k, err := AWSKMSKeys(api, ds, o.AliasPrefix, kmsKeys)
		if err != nil {
			return nil, err
		}
		ks.stops = append(ks.stops, k.Stop)
		for _, d := range ds {
			ks.clients[d.Name] = k.Keys
		}
	}
	ok = true
	return ks, nil
}

// AWSKMSKeys mounts atoom's key/awskms driver over a KMS client, with the purposes it holds. A purpose that keyIDs names is the
// KMS key named (key ID, ARN or alias name); any other is found by its alias, alias/<aliasPrefix>/<purpose>. The driver never
// makes a key.
func AWSKMSKeys(api awskms.API, purposes []purpose.Declaration, aliasPrefix string, keyIDs map[string]string) (*Keys, error) {
	svc, err := awskms.New(awskms.Options{KMS: api, Purposes: purposes, AliasPrefix: aliasPrefix, KeyIDs: keyIDs})
	if err != nil {
		return nil, err
	}
	path, h := svc.Handler()
	hc, stop := Mount(path, h)
	return &Keys{Keys: keyv1alpha1connect.NewKeyStoreServiceClient(hc, "http://key", call.ClientOptions()...), Stop: stop}, nil
}
