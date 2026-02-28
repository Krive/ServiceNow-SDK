package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// IdentityClient provides methods for managing users, roles, and groups in ServiceNow
type IdentityClient struct {
	client *core.Client
}

// User represents a ServiceNow user
type User struct {
	SysID               string                 `json:"sys_id"`
	UserName            string                 `json:"user_name"`
	FirstName           string                 `json:"first_name"`
	LastName            string                 `json:"last_name"`
	MiddleName          string                 `json:"middle_name"`
	Name                string                 `json:"name"`
	Email               string                 `json:"email"`
	Phone               string                 `json:"phone"`
	MobilePhone         string                 `json:"mobile_phone"`
	Title               string                 `json:"title"`
	Department          string                 `json:"department"`
	Location            string                 `json:"location"`
	Building            string                 `json:"building"`
	Room                string                 `json:"room"`
	Company             string                 `json:"company"`
	CostCenter          string                 `json:"cost_center"`
	Manager             string                 `json:"manager"`
	Active              bool                   `json:"active"`
	Locked              bool                   `json:"locked_out"`
	PasswordNeedsReset  bool                   `json:"password_needs_reset"`
	Source              string                 `json:"source"`
	UserPassword        string                 `json:"user_password"`
	LDAPServer          string                 `json:"ldap_server"`
	EnableMultifactor   bool                   `json:"enable_multifactor_authn"`
	FailedAttempts      int                    `json:"failed_attempts"`
	LastLoginTime       time.Time              `json:"last_login_time"`
	LastLoginDevice     string                 `json:"last_login_device"`
	VIP                 bool                   `json:"vip"`
	InternalIntegration bool                   `json:"internal_integration_user"`
	WebServiceAccess    bool                   `json:"web_service_access_only"`
	Avatar              string                 `json:"avatar"`
	Photo               string                 `json:"photo"`
	TimeZone            string                 `json:"time_zone"`
	DateFormat          string                 `json:"date_format"`
	TimeFormat          string                 `json:"time_format"`
	Language            string                 `json:"preferred_language"`
	Country             string                 `json:"country"`
	State               string                 `json:"state"`
	City                string                 `json:"city"`
	Zip                 string                 `json:"zip"`
	Address             string                 `json:"street"`
	Schedule            string                 `json:"schedule"`
	CalendarIntegration string                 `json:"calendar_integration"`
	Roles               []string               `json:"roles,omitempty"`
	Groups              []string               `json:"groups,omitempty"`
	Attributes          map[string]interface{} `json:"attributes,omitempty"`
	CreatedBy           string                 `json:"sys_created_by"`
	CreatedOn           time.Time              `json:"sys_created_on"`
	UpdatedBy           string                 `json:"sys_updated_by"`
	UpdatedOn           time.Time              `json:"sys_updated_on"`
}

// Role represents a ServiceNow role
type Role struct {
	SysID                string                 `json:"sys_id"`
	Name                 string                 `json:"name"`
	Description          string                 `json:"description"`
	Active               bool                   `json:"active"`
	Assignable           bool                   `json:"assignable_by"`
	CanDelegate          bool                   `json:"can_delegate"`
	ElevatedPrivilege    bool                   `json:"elevated_privilege"`
	IncludesRoles        []string               `json:"includes_roles,omitempty"`
	RequiresSubscription string                 `json:"requires_subscription"`
	Scoped               bool                   `json:"scoped"`
	ApplicationScope     string                 `json:"application"`
	Suffix               string                 `json:"suffix"`
	GrantsAdmin          bool                   `json:"grants_admin"`
	Users                []string               `json:"users,omitempty"`
	Groups               []string               `json:"groups,omitempty"`
	Attributes           map[string]interface{} `json:"attributes,omitempty"`
	CreatedBy            string                 `json:"sys_created_by"`
	CreatedOn            time.Time              `json:"sys_created_on"`
	UpdatedBy            string                 `json:"sys_updated_by"`
	UpdatedOn            time.Time              `json:"sys_updated_on"`
}

// Group represents a ServiceNow group
type Group struct {
	SysID           string                 `json:"sys_id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Type            string                 `json:"type"`
	Active          bool                   `json:"active"`
	Email           string                 `json:"email"`
	Parent          string                 `json:"parent"`
	Manager         string                 `json:"manager"`
	CostCenter      string                 `json:"cost_center"`
	DefaultAssignee string                 `json:"default_assignee"`
	IncludeMembers  bool                   `json:"include_members"`
	Points          int                    `json:"points"`
	Source          string                 `json:"source"`
	Members         []string               `json:"members,omitempty"`
	Roles           []string               `json:"roles,omitempty"`
	Attributes      map[string]interface{} `json:"attributes,omitempty"`
	CreatedBy       string                 `json:"sys_created_by"`
	CreatedOn       time.Time              `json:"sys_created_on"`
	UpdatedBy       string                 `json:"sys_updated_by"`
	UpdatedOn       time.Time              `json:"sys_updated_on"`
}

// UserRole represents a user-role assignment
type UserRole struct {
	SysID     string    `json:"sys_id"`
	UserSysID string    `json:"user"`
	RoleSysID string    `json:"role"`
	Granted   string    `json:"granted_by"`
	GrantedOn time.Time `json:"sys_created_on"`
	State     string    `json:"state"`
	Inherited bool      `json:"inherited"`
}

// GroupMember represents a group membership
type GroupMember struct {
	SysID      string    `json:"sys_id"`
	UserSysID  string    `json:"user"`
	GroupSysID string    `json:"group"`
	AddedBy    string    `json:"sys_created_by"`
	AddedOn    time.Time `json:"sys_created_on"`
}

// UserSession represents an active user session
type UserSession struct {
	SysID          string    `json:"sys_id"`
	UserSysID      string    `json:"user"`
	LoginTime      time.Time `json:"login_time"`
	LastAccessTime time.Time `json:"last_access_time"`
	IPAddress      string    `json:"ip_address"`
	UserAgent      string    `json:"user_agent"`
	SessionID      string    `json:"session_id"`
	Active         bool      `json:"active"`
	LoginType      string    `json:"login_type"`
	Device         string    `json:"device"`
	Application    string    `json:"application"`
	IdleTime       int       `json:"idle_time"`
	TimeZone       string    `json:"time_zone"`
}

// UserPreference represents a user preference setting
type UserPreference struct {
	SysID     string `json:"sys_id"`
	UserSysID string `json:"user"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Type      string `json:"type"`
	Personal  bool   `json:"personal"`
}

// UserFilter provides filtering options for user queries
type UserFilter struct {
	Active         *bool     `json:"active,omitempty"`
	Department     string    `json:"department,omitempty"`
	Title          string    `json:"title,omitempty"`
	Company        string    `json:"company,omitempty"`
	Manager        string    `json:"manager,omitempty"`
	Location       string    `json:"location,omitempty"`
	Email          string    `json:"email,omitempty"`
	Role           string    `json:"role,omitempty"`
	Group          string    `json:"group,omitempty"`
	LastLoginAfter time.Time `json:"last_login_after,omitempty"`
	CreatedAfter   time.Time `json:"created_after,omitempty"`
	CreatedBefore  time.Time `json:"created_before,omitempty"`
	VIP            *bool     `json:"vip,omitempty"`
	Source         string    `json:"source,omitempty"`
	Limit          int       `json:"limit,omitempty"`
	Offset         int       `json:"offset,omitempty"`
	OrderBy        string    `json:"order_by,omitempty"`
	Fields         []string  `json:"fields,omitempty"`
}

// RoleFilter provides filtering options for role queries
type RoleFilter struct {
	Active            *bool    `json:"active,omitempty"`
	Assignable        *bool    `json:"assignable,omitempty"`
	ElevatedPrivilege *bool    `json:"elevated_privilege,omitempty"`
	Application       string   `json:"application,omitempty"`
	Name              string   `json:"name,omitempty"`
	Limit             int      `json:"limit,omitempty"`
	Offset            int      `json:"offset,omitempty"`
	OrderBy           string   `json:"order_by,omitempty"`
	Fields            []string `json:"fields,omitempty"`
}

// GroupFilter provides filtering options for group queries
type GroupFilter struct {
	Active     *bool    `json:"active,omitempty"`
	Type       string   `json:"type,omitempty"`
	Parent     string   `json:"parent,omitempty"`
	Manager    string   `json:"manager,omitempty"`
	Name       string   `json:"name,omitempty"`
	CostCenter string   `json:"cost_center,omitempty"`
	Limit      int      `json:"limit,omitempty"`
	Offset     int      `json:"offset,omitempty"`
	OrderBy    string   `json:"order_by,omitempty"`
	Fields     []string `json:"fields,omitempty"`
}

// AccessCheckRequest contains parameters for access control checks
type AccessCheckRequest struct {
	UserSysID   string `json:"user_sys_id"`
	Table       string `json:"table"`
	Operation   string `json:"operation"` // read, write, create, delete
	RecordSysID string `json:"record_sys_id,omitempty"`
}

// AccessCheckResult contains the result of an access control check
type AccessCheckResult struct {
	HasAccess     bool     `json:"has_access"`
	Reason        string   `json:"reason,omitempty"`
	RequiredRoles []string `json:"required_roles,omitempty"`
	GrantedBy     string   `json:"granted_by,omitempty"`
}

// NewIdentityClient creates a new identity client
func NewIdentityClient(client *core.Client) *IdentityClient {
	return &IdentityClient{client: client}
}

// GetUser retrieves a user by sys_id
func (i *IdentityClient) GetUser(sysID string) (*User, error) {
	return i.GetUserWithContext(context.Background(), sysID)
}

// GetUserWithContext retrieves a user by sys_id with context support
func (i *IdentityClient) GetUserWithContext(ctx context.Context, sysID string) (*User, error) {
	var result core.Response
	err := i.client.RawRequestWithContext(ctx, "GET", fmt.Sprintf("/table/sys_user/%s", sysID), nil, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	userData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for user get: %T", result.Result)
	}

	return i.mapDataToUser(userData), nil
}

// GetUserByUsername retrieves a user by username
func (i *IdentityClient) GetUserByUsername(username string) (*User, error) {
	return i.GetUserByUsernameWithContext(context.Background(), username)
}

// GetUserByUsernameWithContext retrieves a user by username with context support
func (i *IdentityClient) GetUserByUsernameWithContext(ctx context.Context, username string) (*User, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("user_name=%s", username),
		"sysparm_limit": "1",
	}

	var result core.Response
	err := i.client.RawRequestWithContext(ctx, "GET", "/table/sys_user", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for user search: %T", result.Result)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("user not found: %s", username)
	}

	userData, ok := results[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected user data type: %T", results[0])
	}

	return i.mapDataToUser(userData), nil
}

// ListUsers retrieves users based on filter criteria
func (i *IdentityClient) ListUsers(filter *UserFilter) ([]*User, error) {
	return i.ListUsersWithContext(context.Background(), filter)
}

// ListUsersWithContext retrieves users based on filter criteria with context support
func (i *IdentityClient) ListUsersWithContext(ctx context.Context, filter *UserFilter) ([]*User, error) {
	params := i.buildUserFilterParams(filter)

	var result core.Response
	err := i.client.RawRequestWithContext(ctx, "GET", "/table/sys_user", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for user list: %T", result.Result)
	}

	var users []*User
	for _, r := range results {
		userData, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		users = append(users, i.mapDataToUser(userData))
	}

	return users, nil
}

// CreateUser creates a new user
func (i *IdentityClient) CreateUser(userData map[string]interface{}) (*User, error) {
	return i.CreateUserWithContext(context.Background(), userData)
}

// CreateUserWithContext creates a new user with context support
func (i *IdentityClient) CreateUserWithContext(ctx context.Context, userData map[string]interface{}) (*User, error) {
	var result core.Response
	err := i.client.RawRequestWithContext(ctx, "POST", "/table/sys_user", userData, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for user create: %T", result.Result)
	}

	return i.mapDataToUser(resultData), nil
}

// UpdateUser updates an existing user
func (i *IdentityClient) UpdateUser(sysID string, updates map[string]interface{}) (*User, error) {
	return i.UpdateUserWithContext(context.Background(), sysID, updates)
}

// UpdateUserWithContext updates an existing user with context support
func (i *IdentityClient) UpdateUserWithContext(ctx context.Context, sysID string, updates map[string]interface{}) (*User, error) {
	var result core.Response
	err := i.client.RawRequestWithContext(ctx, "PUT", fmt.Sprintf("/table/sys_user/%s", sysID), updates, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for user update: %T", result.Result)
	}

	return i.mapDataToUser(resultData), nil
}

// DeleteUser removes a user (sets active = false)
func (i *IdentityClient) DeleteUser(sysID string) error {
	return i.DeleteUserWithContext(context.Background(), sysID)
}

// DeleteUserWithContext removes a user with context support
func (i *IdentityClient) DeleteUserWithContext(ctx context.Context, sysID string) error {
	// In ServiceNow, we typically deactivate users rather than delete them
	updates := map[string]interface{}{
		"active": "false",
	}

	_, err := i.UpdateUserWithContext(ctx, sysID, updates)
	if err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	return nil
}

// Helper method to build user filter parameters
func (i *IdentityClient) buildUserFilterParams(filter *UserFilter) map[string]string {
	params := make(map[string]string)

	if filter == nil {
		return params
	}

	var queryParts []string

	if filter.Active != nil {
		queryParts = append(queryParts, fmt.Sprintf("active=%t", *filter.Active))
	}
	if filter.Department != "" {
		queryParts = append(queryParts, fmt.Sprintf("department=%s", filter.Department))
	}
	if filter.Title != "" {
		queryParts = append(queryParts, fmt.Sprintf("titleLIKE%s", filter.Title))
	}
	if filter.Company != "" {
		queryParts = append(queryParts, fmt.Sprintf("company=%s", filter.Company))
	}
	if filter.Manager != "" {
		queryParts = append(queryParts, fmt.Sprintf("manager=%s", filter.Manager))
	}
	if filter.Location != "" {
		queryParts = append(queryParts, fmt.Sprintf("location=%s", filter.Location))
	}
	if filter.Email != "" {
		queryParts = append(queryParts, fmt.Sprintf("emailLIKE%s", filter.Email))
	}
	if filter.VIP != nil {
		queryParts = append(queryParts, fmt.Sprintf("vip=%t", *filter.VIP))
	}
	if filter.Source != "" {
		queryParts = append(queryParts, fmt.Sprintf("source=%s", filter.Source))
	}
	if filter.Role != "" {
		queryParts = append(queryParts, fmt.Sprintf("sys_user_has_role.role.name=%s", filter.Role))
	}
	if filter.Group != "" {
		queryParts = append(queryParts, fmt.Sprintf("sys_user_grmember.group.name=%s", filter.Group))
	}

	if len(queryParts) > 0 {
		params["sysparm_query"] = strings.Join(queryParts, "^")
	}

	if filter.Limit > 0 {
		params["sysparm_limit"] = fmt.Sprintf("%d", filter.Limit)
	}
	if filter.Offset > 0 {
		params["sysparm_offset"] = fmt.Sprintf("%d", filter.Offset)
	}
	if orderClause := buildEncodedOrderClause(filter.OrderBy); orderClause != "" {
		queryParts = append(queryParts, orderClause)
		params["sysparm_query"] = strings.Join(queryParts, "^")
	}
	if len(filter.Fields) > 0 {
		params["sysparm_fields"] = strings.Join(filter.Fields, ",")
	}

	return params
}

// Helper method to map raw data to User struct
func (i *IdentityClient) mapDataToUser(data map[string]interface{}) *User {
	user := &User{
		Attributes: make(map[string]interface{}),
	}

	// Map standard fields
	if sysID, ok := data["sys_id"].(string); ok {
		user.SysID = sysID
	}
	if userName, ok := data["user_name"].(string); ok {
		user.UserName = userName
	}
	if firstName, ok := data["first_name"].(string); ok {
		user.FirstName = firstName
	}
	if lastName, ok := data["last_name"].(string); ok {
		user.LastName = lastName
	}
	if middleName, ok := data["middle_name"].(string); ok {
		user.MiddleName = middleName
	}
	if name, ok := data["name"].(string); ok {
		user.Name = name
	}
	if email, ok := data["email"].(string); ok {
		user.Email = email
	}
	if phone, ok := data["phone"].(string); ok {
		user.Phone = phone
	}
	if mobilePhone, ok := data["mobile_phone"].(string); ok {
		user.MobilePhone = mobilePhone
	}
	if title, ok := data["title"].(string); ok {
		user.Title = title
	}
	if department, ok := data["department"].(string); ok {
		user.Department = department
	}
	if location, ok := data["location"].(string); ok {
		user.Location = location
	}
	if building, ok := data["building"].(string); ok {
		user.Building = building
	}
	if room, ok := data["room"].(string); ok {
		user.Room = room
	}
	if company, ok := data["company"].(string); ok {
		user.Company = company
	}
	if costCenter, ok := data["cost_center"].(string); ok {
		user.CostCenter = costCenter
	}
	if manager, ok := data["manager"].(string); ok {
		user.Manager = manager
	}
	if active, ok := data["active"].(string); ok {
		user.Active = active == "true"
	}
	if locked, ok := data["locked_out"].(string); ok {
		user.Locked = locked == "true"
	}
	if passwordNeedsReset, ok := data["password_needs_reset"].(string); ok {
		user.PasswordNeedsReset = passwordNeedsReset == "true"
	}
	if source, ok := data["source"].(string); ok {
		user.Source = source
	}
	if ldapServer, ok := data["ldap_server"].(string); ok {
		user.LDAPServer = ldapServer
	}
	if enableMFA, ok := data["enable_multifactor_authn"].(string); ok {
		user.EnableMultifactor = enableMFA == "true"
	}
	if failedAttempts, ok := data["failed_attempts"].(string); ok {
		if attempts, err := fmt.Sscanf(failedAttempts, "%d", &user.FailedAttempts); err == nil && attempts == 1 {
			// Successfully parsed
		}
	}
	if vip, ok := data["vip"].(string); ok {
		user.VIP = vip == "true"
	}
	if internalIntegration, ok := data["internal_integration_user"].(string); ok {
		user.InternalIntegration = internalIntegration == "true"
	}
	if webServiceAccess, ok := data["web_service_access_only"].(string); ok {
		user.WebServiceAccess = webServiceAccess == "true"
	}
	if avatar, ok := data["avatar"].(string); ok {
		user.Avatar = avatar
	}
	if photo, ok := data["photo"].(string); ok {
		user.Photo = photo
	}
	if timeZone, ok := data["time_zone"].(string); ok {
		user.TimeZone = timeZone
	}
	if dateFormat, ok := data["date_format"].(string); ok {
		user.DateFormat = dateFormat
	}
	if timeFormat, ok := data["time_format"].(string); ok {
		user.TimeFormat = timeFormat
	}
	if language, ok := data["preferred_language"].(string); ok {
		user.Language = language
	}
	if country, ok := data["country"].(string); ok {
		user.Country = country
	}
	if state, ok := data["state"].(string); ok {
		user.State = state
	}
	if city, ok := data["city"].(string); ok {
		user.City = city
	}
	if zip, ok := data["zip"].(string); ok {
		user.Zip = zip
	}
	if address, ok := data["street"].(string); ok {
		user.Address = address
	}
	if schedule, ok := data["schedule"].(string); ok {
		user.Schedule = schedule
	}
	if calendarIntegration, ok := data["calendar_integration"].(string); ok {
		user.CalendarIntegration = calendarIntegration
	}
	if createdBy, ok := data["sys_created_by"].(string); ok {
		user.CreatedBy = createdBy
	}
	if updatedBy, ok := data["sys_updated_by"].(string); ok {
		user.UpdatedBy = updatedBy
	}

	// Parse timestamps
	if createdOn, ok := data["sys_created_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", createdOn); err == nil {
			user.CreatedOn = t
		}
	}
	if updatedOn, ok := data["sys_updated_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", updatedOn); err == nil {
			user.UpdatedOn = t
		}
	}
	if lastLoginTime, ok := data["last_login_time"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", lastLoginTime); err == nil {
			user.LastLoginTime = t
		}
	}

	// Store any additional attributes that weren't mapped
	standardFields := map[string]bool{
		"sys_id": true, "user_name": true, "first_name": true, "last_name": true,
		"middle_name": true, "name": true, "email": true, "phone": true,
		"mobile_phone": true, "title": true, "department": true, "location": true,
		"building": true, "room": true, "company": true, "cost_center": true,
		"manager": true, "active": true, "locked_out": true, "password_needs_reset": true,
		"source": true, "ldap_server": true, "enable_multifactor_authn": true,
		"failed_attempts": true, "last_login_time": true, "vip": true,
		"internal_integration_user": true, "web_service_access_only": true,
		"avatar": true, "photo": true, "time_zone": true, "date_format": true,
		"time_format": true, "preferred_language": true, "country": true,
		"state": true, "city": true, "zip": true, "street": true, "schedule": true,
		"calendar_integration": true, "sys_created_by": true, "sys_updated_by": true,
		"sys_created_on": true, "sys_updated_on": true,
	}

	for key, value := range data {
		if !standardFields[key] {
			user.Attributes[key] = value
		}
	}

	return user
}
