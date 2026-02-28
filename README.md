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
