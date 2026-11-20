package hive

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/sclgo/impala-go/internal/generated/cli_service"
	"github.com/sclgo/impala-go/internal/generated/impalaservice"
)

// Client represents Hive Client
type Client struct {
	client impalaservice.ImpalaHiveServer2Service
	opts   *Options
	log    *log.Logger
}

// Options for Hive Client
type Options struct {
	MaxRows int64
	// MemLimit configures the MEM_LIMIT Impala property at session level
	// https://impala.apache.org/docs/build/html/topics/impala_mem_limit.html
	MemLimit string
	// QueryTimeout in seconds - for QUERY_TIMEOUT_S session configuration value
	// https://impala.apache.org/docs/build/html/topics/impala_query_timeout_s.html
	QueryTimeout int
	// FetchRowsTimeout bounds how long the server holds a fetch that has no rows yet, FETCH_ROWS_TIMEOUT_MS,
	// so that a fetch returns before the socket timeout and a cancelled context is seen between fetches.
	// https://impala.apache.org/docs/build/html/topics/impala_fetch_rows_timeout_ms.html
	FetchRowsTimeout time.Duration
}

// detachedClient keeps a call's context from abandoning it part way. Thrift stops reading a reply once the
// context's deadline has passed, which leaves the rest of the reply on the connection and the connection
// unusable. A context that ends is handled between calls instead, by cancelling the operation.
type detachedClient struct {
	thrift.TClient
}

func (c detachedClient) Call(ctx context.Context, method string, args, result thrift.TStruct) (thrift.ResponseMeta, error) {
	return c.TClient.Call(context.WithoutCancel(ctx), method, args, result)
}

// NewClient creates Hive Client
func NewClient(client thrift.TClient, log *log.Logger, opts *Options) *Client {
	return &Client{
		client: impalaservice.NewImpalaHiveServer2ServiceClient(detachedClient{client}),
		log:    log,
		opts:   opts,
	}
}

// OpenSession creates new hive session
func (c *Client) OpenSession(ctx context.Context) (*Session, error) {

	cfg := map[string]string{
		"MEM_LIMIT":       c.opts.MemLimit,
		"QUERY_TIMEOUT_S": strconv.Itoa(c.opts.QueryTimeout),
	}
	if c.opts.FetchRowsTimeout > 0 {
		cfg["FETCH_ROWS_TIMEOUT_MS"] = strconv.FormatInt(c.opts.FetchRowsTimeout.Milliseconds(), 10)
	}

	req := cli_service.TOpenSessionReq{
		ClientProtocol: cli_service.TProtocolVersion_HIVE_CLI_SERVICE_PROTOCOL_V7,
		Configuration:  cfg,
	}

	resp, err := c.client.OpenSession(ctx, &req)
	if err != nil {
		return nil, err
	}
	if err = checkStatus(resp); err != nil {
		return nil, err
	}

	c.log.Printf("open session: %s", guid(resp.SessionHandle.GetSessionId().GUID))
	c.log.Printf("session config: %v", resp.Configuration)
	return &Session{h: resp.SessionHandle, hive: c}, nil
}
