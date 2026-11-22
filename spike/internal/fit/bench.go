package fit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/truvity/atoom/common/call"
	storedyn "github.com/truvity/atoom/store/dynamodb"
	storev1 "github.com/truvity/atoom/store/gen/atoom/store/v1alpha1"
	"github.com/truvity/atoom/store/gen/atoom/store/v1alpha1/storev1alpha1connect"

	"github.com/truvity/session/spike/internal/sess"
)

// BenchOptions says how much to measure.
type BenchOptions struct {
	Prefix     string // name prefix of the two tables the bench makes and drops
	N, Rounds  int    // calls per round and rounds, per path
	Concurrent bool   // also run the concurrent callers
}

type series struct {
	name string
	d    []time.Duration
}

func (s *series) add(d time.Duration) { s.d = append(s.d, d) }

func q(d []time.Duration, p float64) float64 { return float64(d[int(float64(len(d)-1)*p)]) / 1e6 }

func (s *series) print(w io.Writer) {
	d := append([]time.Duration(nil), s.d...)
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	var sum time.Duration
	for _, x := range d {
		sum += x
	}
	fmt.Fprintf(w, "| %-62s | %6d | %6.3f | %6.3f | %6.3f | %6.3f | %6.3f |\n", s.name, len(d),
		float64(sum)/float64(len(d))/1e6, q(d, .5), q(d, .95), q(d, .99), float64(d[len(d)-1])/1e6)
}

// stub is an ItemService whose Get answers a fixed item: the cost of the port without the engine.
type stub struct {
	storev1alpha1connect.UnimplementedItemServiceHandler
	item *storev1.DriverItem
}

func (s *stub) Get(context.Context, *connect.Request[storev1.ItemGetRequest]) (*connect.Response[storev1.ItemGetResponse], error) {
	return connect.NewResponse(&storev1.ItemGetResponse{Item: s.item}), nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func waitActive(ctx context.Context, db *awsdynamodb.Client, table string) error {
	return awsdynamodb.NewTableExistsWaiter(db).Wait(ctx, &awsdynamodb.DescribeTableInput{TableName: &table}, 5*time.Minute)
}

// Bench measures the one strongly consistent read of a check, three ways, on the DynamoDB that db talks to:
// the first spike's direct AWS SDK path, atoom's store port called through its generated client with the DynamoDB
// driver in the same process, and the port's transport alone (a stub driver that makes no DynamoDB call).
// It makes two tables under o.Prefix and drops them. The sequential paths take turns, so a drift hits all of them.
func Bench(ctx context.Context, db *awsdynamodb.Client, o BenchOptions, w io.Writer) error {
	direct := &sess.Store{DB: db, Table: o.Prefix + "-direct", Consist: true,
		IdleTTL: 30 * time.Minute, MaxTTL: 8 * time.Hour, TouchGap: time.Minute}
	dk := sha256.Sum256([]byte("spike-data-key"))
	hk := sha256.Sum256([]byte("spike-hmac-key"))
	direct.DataKey, direct.HMACKey = dk[:], hk[:]
	// the first spike's table without its two secondary indexes, which a read never touches (and which would slow the creation)
	if _, err := db.CreateTable(ctx, &awsdynamodb.CreateTableInput{TableName: &direct.Table, BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS}},
		KeySchema:            []types.KeySchemaElement{{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash}}}); err != nil {
		return err
	}
	defer func() {
		_, _ = db.DeleteTable(context.Background(), &awsdynamodb.DeleteTableInput{TableName: &direct.Table})
	}()
	atoomTable := o.Prefix + "-atoom"
	if err := storedyn.EnsureTable(ctx, db, atoomTable); err != nil {
		return err
	}
	defer func() {
		_, _ = db.DeleteTable(context.Background(), &awsdynamodb.DeleteTableInput{TableName: &atoomTable})
	}()
	for _, t := range []string{direct.Table, atoomTable} {
		if err := waitActive(ctx, db, t); err != nil {
			return err
		}
	}
	e, err := newEnvOn(ctx, db, atoomTable, nil)
	if err != nil {
		return err
	}
	defer e.Stop()

	recd := func() *sess.Record {
		return &sess.Record{Sub: "bench", Iss: "i", Sid: "bench-sid", AccessToken: string(make([]byte, 1500))}
	}
	idD, idA := sess.NewID(), sess.NewID()
	must(direct.Create(ctx, idD, recd()))
	must(e.Store.Create(ctx, idA, recd()))
	res, err := e.Items.Get(ctx, connect.NewRequest(&storev1.ItemGetRequest{Key: []byte(e.Store.KeyOf(idA)), Linearizable: true}))
	if err != nil {
		return err
	}
	path, h := storev1alpha1connect.NewItemServiceHandler(&stub{item: res.Msg.GetItem()})
	hc, stop := Mount(path, h)
	defer stop()
	stubStore := *e.Store
	stubStore.Items = storev1alpha1connect.NewItemServiceClient(hc, "http://store", call.ClientOptions()...)

	coreD := &sess.Core{Store: direct, CookieName: "__Host-spike"}
	coreA := &sess.Core{Checker: e.Store, CookieName: "__Host-spike"}
	req := func(id string) sess.Request {
		return sess.Request{Method: "GET", Path: "/app/x", Header: http.Header{"Cookie": {"__Host-spike=" + id}}}
	}
	type job struct {
		s *series
		f func()
	}
	jobs := []job{
		{&series{name: "GetItem strong + decrypt, AWS SDK direct (first spike)"}, func() { _, err := direct.Get(ctx, idD, false); must(err) }},
		{&series{name: "Get linearizable + decrypt, atoom store port in-process"}, func() { _, err := e.Store.Get(ctx, idA, false); must(err) }},
		{&series{name: "Get through the port's transport only (stub driver, no DynamoDB)"}, func() { _, err := stubStore.Get(ctx, idA, false); must(err) }},
		{&series{name: "Core.Check, direct store"}, func() {
			if d := coreD.Check(ctx, req(idD)); d.Kind != sess.Allow {
				panic(d)
			}
		}},
		{&series{name: "Core.Check, atoom store port in-process"}, func() {
			if d := coreA.Check(ctx, req(idA)); d.Kind != sess.Allow {
				panic(d)
			}
		}},
	}
	for _, j := range jobs { // warm-up
		for i := 0; i < 100; i++ {
			j.f()
		}
	}
	perRound := make([][]float64, len(jobs))
	for r := 0; r < o.Rounds; r++ {
		for ji, j := range jobs {
			start := len(j.s.d)
			for i := 0; i < o.N; i++ {
				t := time.Now()
				j.f()
				j.s.add(time.Since(t))
			}
			d := append([]time.Duration(nil), j.s.d[start:]...)
			sort.Slice(d, func(a, b int) bool { return d[a] < d[b] })
			perRound[ji] = append(perRound[ji], q(d, .5))
		}
	}
	fmt.Fprintf(w, "sequential, one caller, %d rounds of %d calls per path, interleaved. Times in ms.\n\n", o.Rounds, o.N)
	fmt.Fprintf(w, "| %-62s | %6s | %6s | %6s | %6s | %6s | %6s |\n", "path", "n", "mean", "p50", "p95", "p99", "max")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
	for _, j := range jobs {
		j.s.print(w)
	}
	fmt.Fprintln(w, "\np50 of each round (ms), to see the drift between rounds:")
	for ji, j := range jobs {
		fmt.Fprintf(w, "  %-62s", j.s.name)
		for _, v := range perRound[ji] {
			fmt.Fprintf(w, " %.3f", v)
		}
		fmt.Fprintln(w)
	}
	// the write paths of the session store on atoom's port (the first spike's table has other write paths; see its findings)
	wn := o.N / 4
	if wn < 50 {
		wn = 50
	}
	base := time.Now()
	k := 0
	mk := func(sub, sid string) *sess.Record {
		return &sess.Record{Sub: sub, Iss: "i", Sid: sid, AccessToken: string(make([]byte, 1500))}
	}
	writes := []job{
		{&series{name: "create: 1 item + 2 index entries (one Transact)"}, func() {
			must(e.Store.Create(ctx, sess.NewID(), mk("w"+sess.NewID(), sess.NewID())))
		}},
		{&series{name: "create: item + 2 pointer items (read, then one Transact)"}, func() {
			_, err := e.Store.CreateWithPointers(ctx, sess.NewID(), mk("p"+sess.NewID(), sess.NewID()))
			must(err)
		}},
		{&series{name: "idle refresh: Get + Touch (version condition, whole value written)"}, func() {
			k++
			e.Store.Now = func() time.Time { return base.Add(time.Duration(k) * 2 * time.Minute) }
			l, err := e.Store.Get(ctx, idA, false)
			must(err)
			if _, err := e.Store.Touch(ctx, idA, l); err != nil {
				panic(err)
			}
		}},
		{&series{name: "create (index entries) + logout by sid (Query linearizable, delete)"}, func() {
			sid := sess.NewID()
			must(e.Store.Create(ctx, sess.NewID(), mk("l"+sess.NewID(), sid)))
			if n, err := e.Store.LogoutByIndex(ctx, "i", sid, ""); err != nil || n != 1 {
				panic(fmt.Sprint(n, err))
			}
		}},
		{&series{name: "create (pointer items) + logout by sid (Get linearizable, delete)"}, func() {
			sid := sess.NewID()
			_, err := e.Store.CreateWithPointers(ctx, sess.NewID(), mk("m"+sess.NewID(), sid))
			must(err)
			if n, err := e.Store.LogoutByPointer(ctx, "i", sid, ""); err != nil || n != 1 {
				panic(fmt.Sprint(n, err))
			}
		}},
	}
	for _, j := range writes {
		for i := 0; i < 20; i++ {
			j.f()
		}
		for i := 0; i < wn; i++ {
			t := time.Now()
			j.f()
			j.s.add(time.Since(t))
		}
	}
	e.Store.Now = nil
	fmt.Fprintf(w, "\nwrite paths, one caller, %d calls each. Times in ms.\n\n", wn)
	fmt.Fprintf(w, "| %-62s | %6s | %6s | %6s | %6s | %6s | %6s |\n", "path", "n", "mean", "p50", "p95", "p99", "max")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
	for _, j := range writes {
		j.s.print(w)
	}
	if !o.Concurrent {
		return nil
	}
	fmt.Fprintln(w, "\nconcurrent callers (each caller calls in a loop), Get only. Times in ms.")
	fmt.Fprintf(w, "| %-62s | %6s | %6s | %6s | %6s | %6s |\n", "path", "calls", "p50", "p99", "max", "per s")
	fmt.Fprintln(w, "|---|---|---|---|---|---|")
	for _, conc := range []int{8, 32} {
		for _, c := range []struct {
			name string
			f    func()
		}{{"AWS SDK direct", jobs[0].f}, {"atoom port in-process", jobs[1].f}, {"stub transport only", jobs[2].f}} {
			var mu sync.Mutex
			var all []time.Duration
			var wg sync.WaitGroup
			per := o.N * 2 / conc
			if per < 20 {
				per = 20
			}
			t0 := time.Now()
			for g := 0; g < conc; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					loc := make([]time.Duration, 0, per)
					for i := 0; i < per; i++ {
						t := time.Now()
						c.f()
						loc = append(loc, time.Since(t))
					}
					mu.Lock()
					all = append(all, loc...)
					mu.Unlock()
				}()
			}
			wg.Wait()
			el := time.Since(t0)
			sort.Slice(all, func(a, b int) bool { return all[a] < all[b] })
			fmt.Fprintf(w, "| %-62s | %6d | %6.3f | %6.3f | %6.3f | %6.0f |\n", fmt.Sprintf("%s, %d callers", c.name, conc), len(all),
				q(all, .5), q(all, .99), float64(all[len(all)-1])/1e6, float64(len(all))/el.Seconds())
		}
	}
	return nil
}
