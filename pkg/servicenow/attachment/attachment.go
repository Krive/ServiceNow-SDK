package attachment

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// AttachmentClient provides methods for managing file attachments in ServiceNow
type AttachmentClient struct {
	client *core.Client
}

// Attachment represents a ServiceNow attachment record
type Attachment struct {
	SysID           string    `json:"sys_id"`
	FileName        string    `json:"file_name"`
	ContentType     string    `json:"content_type"`
	SizeBytes       int64     `json:"size_bytes"`
	SizeCompressed  int64     `json:"size_compressed"`
	Compressed      bool      `json:"compressed"`
	State           string    `json:"state"`
	TableName       string    `json:"table_name"`
	TableSysID      string    `json:"table_sys_id"`
	DownloadLink    string    `json:"download_link"`
	CreatedBy       string    `json:"sys_created_by"`
	CreatedOn       time.Time `json:"sys_created_on"`
	UpdatedBy       string    `json:"sys_updated_by"`
	UpdatedOn       time.Time `json:"sys_updated_on"`
	Hash            string    `json:"hash"`
	AverageImageColor string  `json:"average_image_color"`
	ImageWidth      int       `json:"image_width"`
	ImageHeight     int       `json:"image_height"`
}

// UploadRequest contains options for uploading an attachment
type UploadRequest struct {
	TableName   string            `json:"table_name"`
	TableSysID  string            `json:"table_sys_id"`
	FileName    string            `json:"file_name,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Encryption  string            `json:"encryption_context,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// UploadResult contains the result of an attachment upload
type UploadResult struct {
	Attachment *Attachment `json:"result"`
	Success    bool        `json:"success"`
	Message    string      `json:"message"`
	Error      string      `json:"error,omitempty"`
}

// UploadFromBytesRequest contains options for uploading from byte data
type UploadFromBytesRequest struct {
	UploadRequest
	Data []byte `json:"-"`
}

// UploadFromReaderRequest contains options for uploading from an io.Reader
type UploadFromReaderRequest struct {
	UploadRequest
	Reader io.Reader `json:"-"`
	Size   int64     `json:"-"` // Optional, for progress tracking
}

// AttachmentFilter provides filtering options for listing attachments
type AttachmentFilter struct {
	TableName    string `json:"table_name,omitempty"`
	TableSysID   string `json:"table_sys_id,omitempty"`
	FileName     string `json:"file_name,omitempty"`
	ContentType  string `json:"content_type,omitempty"`
	CreatedBy    string `json:"sys_created_by,omitempty"`
	CreatedAfter string `json:"created_after,omitempty"`
	CreatedBefore string `json:"created_before,omitempty"`
	MinSize      int64  `json:"min_size,omitempty"`
	MaxSize      int64  `json:"max_size,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
}

// NewAttachmentClient creates a new attachment client
func NewAttachmentClient(client *core.Client) *AttachmentClient {
	return &AttachmentClient{client: client}
}

// ValidateFileName checks if a filename is valid for ServiceNow
func ValidateFileName(fileName string) error {
	if fileName == "" {
		return fmt.Errorf("filename cannot be empty")
	}
	
	// Check for invalid characters
	invalidChars := []string{"<", ">", ":", "\"", "|", "?", "*", "/", "\\"}
	for _, char := range invalidChars {
		if strings.Contains(fileName, char) {
			return fmt.Errorf("filename contains invalid character: %s", char)
		}
	}
	
	// Check length
	if len(fileName) > 255 {
		return fmt.Errorf("filename too long (max 255 characters): %d", len(fileName))
	}
	
	return nil
}

// GetMimeType attempts to determine the MIME type of a file
func GetMimeType(fileName string) string {
	ext := strings.ToLower(filepath.Ext(fileName))
	mimeTypes := map[string]string{
		".txt":  "text/plain",
		".pdf":  "application/pdf",
		".doc":  "application/msword",
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".xls":  "application/vnd.ms-excel",
		".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".ppt":  "application/vnd.ms-powerpoint",
		".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".bmp":  "image/bmp",
		".zip":  "application/zip",
		".rar":  "application/x-rar-compressed",
		".7z":   "application/x-7z-compressed",
		".xml":  "application/xml",
		".json": "application/json",
		".csv":  "text/csv",
		".html": "text/html",
		".css":  "text/css",
		".js":   "application/javascript",
	}
	
	if mimeType, exists := mimeTypes[ext]; exists {
		return mimeType
	}
	
	return "application/octet-stream"
}

// List retrieves attachments for a record
func (a *AttachmentClient) List(tableName, sysID string) ([]map[string]interface{}, error) {
	return a.ListWithContext(context.Background(), tableName, sysID)
}

// ListWithContext retrieves attachments for a record with context support
func (a *AttachmentClient) ListWithContext(ctx context.Context, tableName, sysID string) ([]map[string]interface{}, error) {
	params := map[string]string{
		"table_name":   tableName,
		"table_sys_id": sysID,
	}
	var result core.Response
	err := a.client.RawRequestWithContext(ctx, "GET", "/attachment", nil, params, &result)
	if err != nil {
		return nil, err
	}
	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for attachment list: %T", result.Result)
	}
	var attachments []map[string]interface{}
	for _, r := range results {
		attach, ok := r.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected attachment type: %T", r)
		}
		attachments = append(attachments, attach)
	}
	return attachments, nil
}

// Upload uploads a file as an attachment
func (a *AttachmentClient) Upload(tableName, sysID, filePath string) (map[string]interface{}, error) {
	return a.UploadWithContext(context.Background(), tableName, sysID, filePath)
}

// UploadWithContext uploads a file as an attachment with context support
func (a *AttachmentClient) UploadWithContext(ctx context.Context, tableName, sysID, filePath string) (map[string]interface{}, error) {
	if err := a.client.Auth.Apply(a.client.Client); err != nil {
		return nil, fmt.Errorf("failed to apply auth: %w", err)
	}
	resp, err := a.client.Client.R().
		SetContext(ctx).
		SetMultipartFormData(map[string]string{
			"table_name":   tableName,
			"table_sys_id": sysID,
		}).
		SetFile("file", filePath).
		Post("/attachment/upload")

	if err != nil {
		return nil, err
	}
	var result core.Response
	if err := a.client.HandleResponse(resp, nil, &result, core.FormatJSON); err != nil {
		return nil, err
	}
	attached, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for upload: %T", result.Result)
	}
	return attached, nil
}

// Download downloads an attachment to a file
func (a *AttachmentClient) Download(sysID, savePath string) error {
	return a.DownloadWithContext(context.Background(), sysID, savePath)
}

// DownloadWithContext downloads an attachment to a file with context support
func (a *AttachmentClient) DownloadWithContext(ctx context.Context, sysID, savePath string) error {
	resp, err := a.client.Client.R().SetContext(ctx).SetOutput(savePath).Get(fmt.Sprintf("/attachment/%s/file", sysID))
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("download failed: %s - %s", resp.Status(), string(resp.Body()))
	}
	return nil
}

// Delete removes an attachment
func (a *AttachmentClient) Delete(sysID string) error {
	return a.DeleteWithContext(context.Background(), sysID)
}

// DeleteWithContext removes an attachment with context support
func (a *AttachmentClient) DeleteWithContext(ctx context.Context, sysID string) error {
	return a.client.RawRequestWithContext(ctx, "DELETE", fmt.Sprintf("/attachment/%s", sysID), nil, nil, nil)
}
