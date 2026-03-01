//go:build integration

package servicenow_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	sn "codeberg.org/Krive/ServiceNow-SDK/pkg/servicenow"
)

type integrationConfig struct {
	instanceURL string
	username    string
	password    string
}

func loadIntegrationConfig(t *testing.T) integrationConfig {
	t.Helper()

	cfg := integrationConfig{
		instanceURL: os.Getenv("SN_INSTANCE_URL"),
		username:    os.Getenv("SN_USERNAME"),
		password:    os.Getenv("SN_PASSWORD"),
	}

	if cfg.instanceURL == "" || cfg.username == "" || cfg.password == "" {
		t.Skip("integration config missing; set SN_INSTANCE_URL, SN_USERNAME, SN_PASSWORD")
	}

	return cfg
}

func integrationClient(t *testing.T) *sn.Client {
	cfg := loadIntegrationConfig(t)

	client, err := sn.NewClient(sn.Config{
		InstanceURL: cfg.instanceURL,
		Username:    cfg.username,
		Password:    cfg.password,
		Timeout:     30 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create integration client: %v", err)
	}
	return client
}

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Skipf("%s is not set", key)
	}
	return value
}

func TestIntegrationTableListSmoke(t *testing.T) {
	client := integrationClient(t)

	records, err := client.Table("sys_user").
		List(map[string]string{
			"sysparm_fields": "sys_id",
			"sysparm_limit":  "1",
		})
	if err != nil {
		t.Fatalf("table smoke query failed: %v", err)
	}

	if len(records) > 1 {
		t.Fatalf("expected at most one record, got %d", len(records))
	}
}

func TestIntegrationCatalogListSmoke(t *testing.T) {
	client := integrationClient(t)

	catalogs, err := client.Catalog().ListCatalogs()
	if err != nil {
		t.Fatalf("catalog list failed: %v", err)
	}
	if len(catalogs) == 0 {
		t.Skip("no catalogs visible for integration user")
	}

	items, err := client.Catalog().ListItems(catalogs[0].SysID)
	if err != nil {
		t.Fatalf("catalog items list failed for %s: %v", catalogs[0].SysID, err)
	}
	_ = items
}

func TestIntegrationCatalogCartMutationSmoke(t *testing.T) {
	client := integrationClient(t)
	itemSysID := requireEnv(t, "SN_CATALOG_ITEM_SYS_ID")

	added, err := client.Catalog().AddToCart(itemSysID, 1, nil)
	if err != nil {
		t.Fatalf("add to cart failed: %v", err)
	}
	if !added.Success {
		t.Fatalf("add to cart returned unsuccessful response: %+v", added)
	}

	if added.ItemID == "" {
		t.Skip("cart item id not returned by instance; skipping remove step")
	}

	if err := client.Catalog().RemoveFromCart(added.ItemID); err != nil {
		t.Fatalf("remove from cart failed: %v", err)
	}
}

func TestIntegrationCMDBListSmoke(t *testing.T) {
	client := integrationClient(t)

	cis, err := client.CMDB().ListCIs(nil)
	if err != nil {
		t.Fatalf("cmdb list failed: %v", err)
	}
	_ = cis
}

func TestIntegrationCMDBGetSmoke(t *testing.T) {
	client := integrationClient(t)
	ciSysID := requireEnv(t, "SN_CMDB_CI_SYS_ID")

	ci, err := client.CMDB().GetCI(ciSysID)
	if err != nil {
		t.Fatalf("cmdb get failed: %v", err)
	}
	if ci.SysID == "" {
		t.Fatalf("cmdb get returned empty sys_id")
	}
}

func TestIntegrationBatchReadSmoke(t *testing.T) {
	client := integrationClient(t)

	result, err := client.Batch().
		NewBatch().
		Get("users", "/api/now/table/sys_user?sysparm_limit=1").
		Get("groups", "/api/now/table/sys_user_group?sysparm_limit=1").
		Execute()
	if err != nil {
		t.Fatalf("batch read smoke failed: %v", err)
	}

	if result.TotalRequests != 2 {
		t.Fatalf("unexpected total requests in batch result: %d", result.TotalRequests)
	}
	if result.SuccessfulRequests == 0 {
		t.Fatalf("expected at least one successful batch request")
	}
}

func TestIntegrationAttachmentListSmoke(t *testing.T) {
	client := integrationClient(t)
	table := requireEnv(t, "SN_ATTACHMENT_TABLE")
	recordSysID := requireEnv(t, "SN_ATTACHMENT_RECORD_SYS_ID")

	attachments, err := client.Attachment().List(table, recordSysID)
	if err != nil {
		t.Fatalf("attachment list failed: %v", err)
	}
	_ = attachments
}

func TestIntegrationAttachmentUploadDownloadDeleteSmoke(t *testing.T) {
	client := integrationClient(t)
	table := requireEnv(t, "SN_ATTACHMENT_TABLE")
	recordSysID := requireEnv(t, "SN_ATTACHMENT_RECORD_SYS_ID")

	tempFile := filepath.Join(t.TempDir(), "sn-sdk-upload.txt")
	content := []byte(fmt.Sprintf("servicenow-sdk-integration-%d", time.Now().UnixNano()))
	if err := os.WriteFile(tempFile, content, 0600); err != nil {
		t.Fatalf("failed to write temp upload file: %v", err)
	}

	uploaded, err := client.Attachment().Upload(table, recordSysID, tempFile)
	if err != nil {
		t.Fatalf("attachment upload failed: %v", err)
	}

	attachmentSysID, _ := uploaded["sys_id"].(string)
	if attachmentSysID == "" {
		t.Fatalf("upload response missing sys_id: %+v", uploaded)
	}

	downloadPath := filepath.Join(t.TempDir(), "sn-sdk-download.txt")
	if err := client.Attachment().Download(attachmentSysID, downloadPath); err != nil {
		t.Fatalf("attachment download failed: %v", err)
	}
	downloadedContent, err := os.ReadFile(downloadPath)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if len(downloadedContent) == 0 {
		t.Fatalf("downloaded attachment is empty")
	}

	if err := client.Attachment().Delete(attachmentSysID); err != nil {
		t.Fatalf("attachment delete failed: %v", err)
	}
}
