package fit

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	storedyn "github.com/truvity/atoom/store/dynamodb"
)

// Counting wraps the DynamoDB client that atoom's driver calls, to count the calls the driver makes for one
// contract call, and optionally to add a delay to each (a slow store) or to fail each (a store that is down).
type Counting struct {
	In    storedyn.API
	Delay atomic.Int64 // nanoseconds added before every call
	Fail  atomic.Bool  // every call fails
	n     [6]atomic.Int64
}

var opNames = [6]string{"GetItem", "BatchGetItem", "Query", "PutItem", "DeleteItem", "TransactWriteItems"}

func (c *Counting) before(ctx context.Context, op int) error {
	c.n[op].Add(1)
	if d := time.Duration(c.Delay.Load()); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if c.Fail.Load() {
		return errors.New("injected engine failure")
	}
	return nil
}

// Reset zeroes the counters.
func (c *Counting) Reset() {
	for i := range c.n {
		c.n[i].Store(0)
	}
}

// Calls is a snapshot of the counters, by DynamoDB operation, zero counts left out.
func (c *Counting) Calls() map[string]int64 {
	m := map[string]int64{}
	for i := range c.n {
		if v := c.n[i].Load(); v > 0 {
			m[opNames[i]] = v
		}
	}
	return m
}

func (c *Counting) GetItem(ctx context.Context, in *awsdynamodb.GetItemInput, o ...func(*awsdynamodb.Options)) (*awsdynamodb.GetItemOutput, error) {
	if err := c.before(ctx, 0); err != nil {
		return nil, err
	}
	return c.In.GetItem(ctx, in, o...)
}
func (c *Counting) BatchGetItem(ctx context.Context, in *awsdynamodb.BatchGetItemInput, o ...func(*awsdynamodb.Options)) (*awsdynamodb.BatchGetItemOutput, error) {
	if err := c.before(ctx, 1); err != nil {
		return nil, err
	}
	return c.In.BatchGetItem(ctx, in, o...)
}
func (c *Counting) Query(ctx context.Context, in *awsdynamodb.QueryInput, o ...func(*awsdynamodb.Options)) (*awsdynamodb.QueryOutput, error) {
	if err := c.before(ctx, 2); err != nil {
		return nil, err
	}
	return c.In.Query(ctx, in, o...)
}
func (c *Counting) PutItem(ctx context.Context, in *awsdynamodb.PutItemInput, o ...func(*awsdynamodb.Options)) (*awsdynamodb.PutItemOutput, error) {
	if err := c.before(ctx, 3); err != nil {
		return nil, err
	}
	return c.In.PutItem(ctx, in, o...)
}
func (c *Counting) DeleteItem(ctx context.Context, in *awsdynamodb.DeleteItemInput, o ...func(*awsdynamodb.Options)) (*awsdynamodb.DeleteItemOutput, error) {
	if err := c.before(ctx, 4); err != nil {
		return nil, err
	}
	return c.In.DeleteItem(ctx, in, o...)
}
func (c *Counting) TransactWriteItems(ctx context.Context, in *awsdynamodb.TransactWriteItemsInput, o ...func(*awsdynamodb.Options)) (*awsdynamodb.TransactWriteItemsOutput, error) {
	if err := c.before(ctx, 5); err != nil {
		return nil, err
	}
	return c.In.TransactWriteItems(ctx, in, o...)
}

var _ storedyn.API = (*Counting)(nil)
