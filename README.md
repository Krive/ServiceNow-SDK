# ServiceNow SDK for Go

Go SDK for interacting with ServiceNow APIs with a clean client interface, fluent querying, and built-in reliability controls (timeouts, retries, and endpoint-aware rate limiting).

## Highlights

- Multiple auth modes:
  - Basic auth
  - OAuth (client credentials)
  - OAuth (refresh token flow)
  - API key
- Core ServiceNow coverage:
  - Table API (CRUD, schema helpers, fluent query support)
  - Attachments
  - Import Set
  - Aggregate/Stats
  - Batch API
  - Service Catalog (catalogs, items, cart, orders, request tracking)
  - CMDB (CIs, classes, relationships, identification, reconciliation)
  - Identity/IAM (users, groups, roles, access/session operations)
- Built-in resilience:
  - Context-aware requests
  - Configurable retry with exponential backoff + jitter
  - Configurable endpoint-specific rate limiting
  - Typed ServiceNow error classification

## Requirements

- Go `1.24+`
- A reachable ServiceNow instance URL, for example:
  - `https://your-instance.service-now.com`

## Installation

```bash
go get github.com/Krive/ServiceNow-SDK@latest
```

## Quick Start

```go
package main

import (
	"fmt"
	"log"
	"time"

	sn "github.com/Krive/ServiceNow-SDK/pkg/servicenow"
)

func main() {
	client, err := sn.NewClient(sn.Config{
		InstanceURL: "https://your-instance.service-now.com",
		Username:    "api_user",
		Password:    "api_password",
		Timeout:     45 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	incidents, err := client.Table("incident").
		Equals("active", true).
		And().
		Equals("priority", 1).
		OrderByDesc("sys_updated_on").
		Limit(10).
		Execute()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("found %d incidents\n", len(incidents))
}
```

## Authentication

Create the client with `servicenow.Config` and set one auth method:

```go
// Basic auth
sn.NewClient(sn.Config{
	InstanceURL: "https://your-instance.service-now.com",
	Username:    "api_user",
	Password:    "api_password",
})

// OAuth client credentials
sn.NewClient(sn.Config{
	InstanceURL:  "https://your-instance.service-now.com",
	ClientID:     "client-id",
	ClientSecret: "client-secret",
})

// OAuth refresh token flow
sn.NewClient(sn.Config{
	InstanceURL:  "https://your-instance.service-now.com",
	ClientID:     "client-id",
	ClientSecret: "client-secret",
	RefreshToken: "refresh-token",
})

// API key
sn.NewClient(sn.Config{
	InstanceURL: "https://your-instance.service-now.com",
	APIKey:      "api-key",
})
```

### OAuth Token Storage

For OAuth flows, tokens are cached by default in `~/.servicenowtoolkit/tokens` with file mode `0600`.
For environments where tokens must not be persisted to disk, use in-memory storage:

```go
import (
	sn "github.com/Krive/ServiceNow-SDK/pkg/servicenow"
	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

tokenStore := core.NewMemoryTokenStorage()

client, err := sn.NewClient(sn.Config{
	InstanceURL:  "https://your-instance.service-now.com",
	ClientID:     "client-id",
	ClientSecret: "client-secret",
	TokenStorage: tokenStore,
})
```

## Common Usage

### Table CRUD

```go
table := client.Table("incident")

created, err := table.Create(map[string]interface{}{
	"short_description": "Network outage in branch office",
	"priority":          "2",
})

record, err := table.Get(created["sys_id"].(string))

updated, err := table.Update(record["sys_id"].(string), map[string]interface{}{
	"state": "2",
})

err = table.Delete(updated["sys_id"].(string))
```

### Query Builder

```go
qb := client.Table("change_request").
	Equals("active", true).
	And().
	Contains("short_description", "database").
	OrderByDesc("sys_updated_on").
	Limit(20)

changes, err := qb.Execute()
```

### Attachments

```go
attachment := client.Attachment()

uploaded, err := attachment.Upload("incident", "record-sys-id", "./error.log")

err = attachment.Download(uploaded["sys_id"].(string), "./downloaded-error.log")
```

### Aggregate API

```go
stats, err := client.Aggregate("incident").
	NewQuery().
	CountAll("count").
	GroupByField("priority", "").
	Execute()

if err != nil {
	// handle error
}

_ = stats
```

### Batch API

```go
result, err := client.Batch().
	NewBatch().
	Create("new-incident", "incident", map[string]interface{}{
		"short_description": "Created via batch",
	}).
	Get("read-users", "/api/now/table/sys_user?sysparm_limit=2").
	Execute()

if err != nil {
	// handle error
}

fmt.Println(result.SuccessfulRequests, result.FailedRequests)
```

## Reliability Tuning

Use convenience presets:

```go
client.WithConservativeRateLimit().WithAggressiveRetry()
```

Or configure manually via:

- `client.SetTimeout(...)`
- `client.SetRetryConfig(...)`
- `client.SetRateLimitConfig(...)`

## Error Handling

```go
import "github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"

if err != nil {
	if snErr, ok := core.IsServiceNowError(err); ok {
		fmt.Printf("status=%d type=%s retryable=%t\n", snErr.StatusCode, snErr.Type, snErr.Retryable)
	}
}
```

## Package Overview

- `pkg/servicenow`: main client and domain modules
- `pkg/servicenow/core`: low-level HTTP/auth/error primitives
- `pkg/servicenow/query`: fluent encoded query builder
- `pkg/utils/retry`: retry helpers and policy config
- `pkg/utils/ratelimit`: token-bucket and ServiceNow endpoint limiters
- `pkg/types`: shared error contracts/types

## Development

Run all tests:

```bash
GOCACHE=/tmp/go-build go test ./...
```

Run integration smoke tests:

```bash
SN_INSTANCE_URL="https://your-instance.service-now.com" \
SN_USERNAME="api_user" \
SN_PASSWORD="api_password" \
GOCACHE=/tmp/go-build go test -tags=integration ./...
```

Optional integration env vars for extended smoke coverage:

- `SN_CATALOG_ITEM_SYS_ID`: enables cart mutation smoke test (`add_to_cart`/`remove`)
- `SN_CMDB_CI_SYS_ID`: enables CMDB `GetCI` smoke test
- `SN_ATTACHMENT_TABLE` and `SN_ATTACHMENT_RECORD_SYS_ID`: enables attachment list/upload/download/delete smoke tests

### API-Key Endpoint Smoke Script (PDI)

For broad endpoint validation against a real instance, use:
- `scripts/pdi_api_key_endpoint_smoke_test.sh`

Basic mode (safe default behavior):

```bash
SN_INSTANCE_URL="https://devXXXXX.service-now.com" \
SN_API_KEY="REPLACE_WITH_API_KEY" \
SN_CONFIRM_INSTANCE_HOST="devXXXXX.service-now.com" \
SN_TEST_LEVEL="basic" \
SN_RUN_MUTATION=0 \
bash scripts/pdi_api_key_endpoint_smoke_test.sh
```

Full mode (deep coverage, includes mutations):

```bash
SN_INSTANCE_URL="https://devXXXXX.service-now.com" \
SN_API_KEY="REPLACE_WITH_API_KEY" \
SN_CONFIRM_INSTANCE_HOST="devXXXXX.service-now.com" \
SN_TEST_LEVEL="full" \
SN_RUN_MUTATION=1 \
SN_VERBOSE=0 \
SN_TEST_TABLE="incident" \
SN_ATTACHMENT_MIME_TYPE="text/plain" \
SN_ATTACHMENT_FILE_EXT="txt" \
SN_IMPORT_SET_TABLE="u_your_import_table" \
SN_CATALOG_ITEM_SYS_ID="your_catalog_item_sys_id" \
SN_CMDB_CREATE_CLASS="cmdb_ci_computer" \
SN_CMDB_CREATE_PAYLOAD_JSON='{"name":"sdk-cmdb-full-smoke","short_description":"SDK full smoke"}' \
SN_IDENTITY_DEEP_MUTATION=1 \
bash scripts/pdi_api_key_endpoint_smoke_test.sh
```

Safety defaults in the smoke script:
- `SN_RUN_MUTATION` defaults to `0`.
- `SN_ENFORCE_PDI_ONLY` defaults to `1` and allows only `devNNNNNN.service-now.com` unless overridden.
- `SN_ALLOW_NON_PDI` defaults to `0`.
- `SN_ALLOW_PROD_MUTATION` defaults to `0`.
- `SN_CONFIRM_INSTANCE_HOST` can enforce exact hostname matching.

Interactive setup support:
- If `SN_INSTANCE_URL` or `SN_API_KEY` is missing in an interactive shell, the script prompts for values.
- Prompted values can be saved to `SN_ENV_FILE` (default `.sn_smoke_env`) and reused with `source .sn_smoke_env`.
- Controls: `SN_SETUP_IF_MISSING=1|0`, `SN_SETUP_SAVE_ENV=ask|1|0`, `SN_ENV_FILE=<path>`.
