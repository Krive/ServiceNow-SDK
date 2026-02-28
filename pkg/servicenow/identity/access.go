package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// AccessClient handles access control and session management operations
type AccessClient struct {
	client *IdentityClient
}

// NewAccessClient creates a new access client
func (i *IdentityClient) NewAccessClient() *AccessClient {
	return &AccessClient{client: i}
}

// CheckAccess performs a heuristic role-based access check.
// Deprecated: use CheckAccessHeuristic to make non-authoritative behavior explicit.
func (a *AccessClient) CheckAccess(request *AccessCheckRequest) (*AccessCheckResult, error) {
	return a.CheckAccessHeuristicWithContext(context.Background(), request)
}

// CheckAccessWithContext performs a heuristic role-based access check with context support.
// Deprecated: use CheckAccessHeuristicWithContext to make non-authoritative behavior explicit.
func (a *AccessClient) CheckAccessWithContext(ctx context.Context, request *AccessCheckRequest) (*AccessCheckResult, error) {
	return a.CheckAccessHeuristicWithContext(ctx, request)
}

// CheckAccessHeuristic performs a heuristic role-based access check.
// It does not evaluate full ServiceNow ACL logic or script conditions.
func (a *AccessClient) CheckAccessHeuristic(request *AccessCheckRequest) (*AccessCheckResult, error) {
	return a.CheckAccessHeuristicWithContext(context.Background(), request)
}

// CheckAccessHeuristicWithContext performs a heuristic role-based access check with context support.
// It does not evaluate full ServiceNow ACL logic or script conditions.
func (a *AccessClient) CheckAccessHeuristicWithContext(ctx context.Context, request *AccessCheckRequest) (*AccessCheckResult, error) {
	// This would typically use ServiceNow's Access Control API or script includes
	// For now, we'll implement a basic check using role assignments

	user, err := a.client.GetUserWithContext(ctx, request.UserSysID)
	if err != nil {
		return &AccessCheckResult{
			HasAccess:     false,
			Authoritative: false,
			Reason:        fmt.Sprintf("User not found: %s", err.Error()),
		}, nil
	}

	if !user.Active {
		return &AccessCheckResult{
			HasAccess:     false,
			Authoritative: false,
			Reason:        "User is inactive",
		}, nil
	}

	// Get user roles
	roleClient := a.client.NewRoleClient()
	userRoles, err := roleClient.GetUserRolesWithContext(ctx, request.UserSysID)
	if err != nil {
		return &AccessCheckResult{
			HasAccess:     false,
			Authoritative: false,
			Reason:        fmt.Sprintf("Failed to get user roles: %s", err.Error()),
		}, nil
	}

	// Check for admin role
	for _, userRole := range userRoles {
		role, err := roleClient.GetRoleWithContext(ctx, userRole.RoleSysID)
		if err != nil {
			continue
		}

		if role.Name == "admin" || role.GrantsAdmin {
			return &AccessCheckResult{
				HasAccess:     true,
				Authoritative: false,
				GrantedBy:     "heuristic role check: admin role",
				Reason:        "heuristic check only; this is not authoritative ACL evaluation",
			}, nil
		}
	}

	// For specific operations, check table-specific roles
	if request.Table != "" {
		tableRoles := a.getTableRoles(request.Table, request.Operation)
		for _, userRole := range userRoles {
			role, err := roleClient.GetRoleWithContext(ctx, userRole.RoleSysID)
			if err != nil {
				continue
			}

			for _, requiredRole := range tableRoles {
				if role.Name == requiredRole {
					return &AccessCheckResult{
						HasAccess:     true,
						Authoritative: false,
						GrantedBy:     fmt.Sprintf("heuristic role check: %s", role.Name),
						Reason:        "heuristic check only; this is not authoritative ACL evaluation",
					}, nil
				}
			}
		}

		return &AccessCheckResult{
			HasAccess:     false,
			Authoritative: false,
			Reason:        fmt.Sprintf("User lacks required role for %s on %s", request.Operation, request.Table),
			RequiredRoles: tableRoles,
		}, nil
	}

	return &AccessCheckResult{
		HasAccess:     true,
		Authoritative: false,
		Reason:        "heuristic check only; default access granted (non-authoritative)",
	}, nil
}

// getTableRoles returns the roles typically required for operations on specific tables
func (a *AccessClient) getTableRoles(table, operation string) []string {
	// This is a simplified mapping - in reality this would come from ACL rules
	tableRoleMap := map[string]map[string][]string{
		"incident": {
			"read":   {"itil", "incident_manager"},
			"write":  {"itil", "incident_manager"},
			"create": {"itil"},
			"delete": {"incident_manager", "admin"},
		},
		"change_request": {
			"read":   {"itil", "change_manager"},
			"write":  {"itil", "change_manager"},
			"create": {"itil"},
			"delete": {"change_manager", "admin"},
		},
		"sys_user": {
			"read":   {"user_admin", "admin"},
			"write":  {"user_admin", "admin"},
			"create": {"user_admin", "admin"},
			"delete": {"admin"},
		},
		"sys_user_group": {
			"read":   {"user_admin", "admin"},
			"write":  {"user_admin", "admin"},
			"create": {"user_admin", "admin"},
			"delete": {"admin"},
		},
	}

	if tableOps, exists := tableRoleMap[table]; exists {
		if roles, exists := tableOps[operation]; exists {
			return roles
		}
	}

	// Default roles for unknown tables
	switch operation {
	case "read":
		return []string{"itil"}
	case "write", "create":
		return []string{"itil"}
	case "delete":
		return []string{"admin"}
	default:
		return []string{"itil"}
	}
}

// GetActiveSessions retrieves active user sessions
func (a *AccessClient) GetActiveSessions() ([]*UserSession, error) {
	return a.GetActiveSessionsWithContext(context.Background())
}

// GetActiveSessionsWithContext retrieves active sessions with context support
func (a *AccessClient) GetActiveSessionsWithContext(ctx context.Context) ([]*UserSession, error) {
	params := map[string]string{
		"sysparm_query": "active=true",
	}

	var result core.Response
	err := a.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_session", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for sessions: %T", result.Result)
	}

	var sessions []*UserSession
	for _, result := range results {
		sessionData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		sessions = append(sessions, a.mapDataToUserSession(sessionData))
	}

	return sessions, nil
}

// GetUserSessions retrieves sessions for a specific user
func (a *AccessClient) GetUserSessions(userSysID string) ([]*UserSession, error) {
	return a.GetUserSessionsWithContext(context.Background(), userSysID)
}

// GetUserSessionsWithContext retrieves user sessions with context support
func (a *AccessClient) GetUserSessionsWithContext(ctx context.Context, userSysID string) ([]*UserSession, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("user=%s", sanitizeEncodedQueryValue(userSysID)),
	}

	var result core.Response
	err := a.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_session", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for user sessions: %T", result.Result)
	}

	var sessions []*UserSession
	for _, result := range results {
		sessionData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		sessions = append(sessions, a.mapDataToUserSession(sessionData))
	}

	return sessions, nil
}

// GetUserPreferences retrieves preferences for a user
func (a *AccessClient) GetUserPreferences(userSysID string) ([]*UserPreference, error) {
	return a.GetUserPreferencesWithContext(context.Background(), userSysID)
}

// GetUserPreferencesWithContext retrieves user preferences with context support
func (a *AccessClient) GetUserPreferencesWithContext(ctx context.Context, userSysID string) ([]*UserPreference, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("user=%s", sanitizeEncodedQueryValue(userSysID)),
	}

	var result core.Response
	err := a.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_preference", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get user preferences: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for user preferences: %T", result.Result)
	}

	var preferences []*UserPreference
	for _, result := range results {
		prefData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		preferences = append(preferences, a.mapDataToUserPreference(prefData))
	}

	return preferences, nil
}

// SetUserPreference sets a preference for a user
func (a *AccessClient) SetUserPreference(userSysID, name, value string) (*UserPreference, error) {
	return a.SetUserPreferenceWithContext(context.Background(), userSysID, name, value)
}

// SetUserPreferenceWithContext sets a user preference with context support
func (a *AccessClient) SetUserPreferenceWithContext(ctx context.Context, userSysID, name, value string) (*UserPreference, error) {
	// Check if preference already exists
	existingPrefs, err := a.GetUserPreferencesWithContext(ctx, userSysID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing preferences: %w", err)
	}

	for _, pref := range existingPrefs {
		if pref.Name == name {
			// Update existing preference
			updates := map[string]interface{}{
				"value": value,
			}

			var result core.Response
			err := a.client.client.RawRequestWithContext(ctx, "PUT", fmt.Sprintf("/table/sys_user_preference/%s", escapeIdentityPathSegment(pref.SysID)), updates, nil, &result)
			if err != nil {
				return nil, fmt.Errorf("failed to update user preference: %w", err)
			}

			resultData, ok := result.Result.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("unexpected result type for preference update: %T", result.Result)
			}

			return a.mapDataToUserPreference(resultData), nil
		}
	}

	// Create new preference
	prefData := map[string]interface{}{
		"user":     userSysID,
		"name":     name,
		"value":    value,
		"personal": "true",
	}

	var result core.Response
	err = a.client.client.RawRequestWithContext(ctx, "POST", "/table/sys_user_preference", prefData, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to create user preference: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for preference create: %T", result.Result)
	}

	return a.mapDataToUserPreference(resultData), nil
}

// DeleteUserPreference removes a user preference
func (a *AccessClient) DeleteUserPreference(userSysID, name string) error {
	return a.DeleteUserPreferenceWithContext(context.Background(), userSysID, name)
}

// DeleteUserPreferenceWithContext removes a user preference with context support
func (a *AccessClient) DeleteUserPreferenceWithContext(ctx context.Context, userSysID, name string) error {
	// Find the preference
	params := map[string]string{
		"sysparm_query": fmt.Sprintf(
			"user=%s^name=%s",
			sanitizeEncodedQueryValue(userSysID),
			sanitizeEncodedQueryValue(name),
		),
		"sysparm_limit": "1",
	}

	var result core.Response
	err := a.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_preference", nil, params, &result)
	if err != nil {
		return fmt.Errorf("failed to find user preference: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return fmt.Errorf("unexpected result type for preference search: %T", result.Result)
	}

	if len(results) == 0 {
		return fmt.Errorf("preference not found")
	}

	prefData, ok := results[0].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected preference data type: %T", results[0])
	}

	prefSysID, ok := prefData["sys_id"].(string)
	if !ok {
		return fmt.Errorf("preference sys_id not found")
	}

	// Delete the preference
	err = a.client.client.RawRequestWithContext(ctx, "DELETE", fmt.Sprintf("/table/sys_user_preference/%s", escapeIdentityPathSegment(prefSysID)), nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to delete user preference: %w", err)
	}

	return nil
}

// InvalidateUserSessions invalidates all active sessions for a user
func (a *AccessClient) InvalidateUserSessions(userSysID string) error {
	return a.InvalidateUserSessionsWithContext(context.Background(), userSysID)
}

// InvalidateUserSessionsWithContext invalidates user sessions with context support
func (a *AccessClient) InvalidateUserSessionsWithContext(ctx context.Context, userSysID string) error {
	// Get active sessions for the user
	sessions, err := a.GetUserSessionsWithContext(ctx, userSysID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Deactivate each session
	for _, session := range sessions {
		if session.Active {
			updates := map[string]interface{}{
				"active": false,
			}

			err := a.client.client.RawRequestWithContext(ctx, "PUT", fmt.Sprintf("/table/sys_user_session/%s", escapeIdentityPathSegment(session.SysID)), updates, nil, nil)
			if err != nil {
				// Continue with other sessions if one fails
				continue
			}
		}
	}

	return nil
}

// GetUserPermissions retrieves all effective permissions for a user
func (a *AccessClient) GetUserPermissions(userSysID string) (map[string][]string, error) {
	return a.GetUserPermissionsWithContext(context.Background(), userSysID)
}

// GetUserPermissionsWithContext retrieves user permissions with context support
func (a *AccessClient) GetUserPermissionsWithContext(ctx context.Context, userSysID string) (map[string][]string, error) {
	permissions := make(map[string][]string)

	// Get user roles
	roleClient := a.client.NewRoleClient()
	userRoles, err := roleClient.GetUserRolesWithContext(ctx, userSysID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Get role details and build permissions map
	for _, userRole := range userRoles {
		role, err := roleClient.GetRoleWithContext(ctx, userRole.RoleSysID)
		if err != nil {
			continue
		}

		if _, exists := permissions["roles"]; !exists {
			permissions["roles"] = []string{}
		}
		permissions["roles"] = append(permissions["roles"], role.Name)

		// Add role-specific permissions
		if role.Name == "admin" || role.GrantsAdmin {
			permissions["admin"] = []string{"full_access"}
		}

		if role.ElevatedPrivilege {
			if _, exists := permissions["elevated"]; !exists {
				permissions["elevated"] = []string{}
			}
			permissions["elevated"] = append(permissions["elevated"], role.Name)
		}
	}

	// Get user groups
	groupClient := a.client.NewGroupClient()
	userGroups, err := groupClient.GetUserGroupsWithContext(ctx, userSysID)
	if err == nil {
		for _, membership := range userGroups {
			group, err := groupClient.GetGroupWithContext(ctx, membership.GroupSysID)
			if err != nil {
				continue
			}

			if _, exists := permissions["groups"]; !exists {
				permissions["groups"] = []string{}
			}
			permissions["groups"] = append(permissions["groups"], group.Name)
		}
	}

	return permissions, nil
}

// Helper method to map raw data to UserSession struct
func (a *AccessClient) mapDataToUserSession(data map[string]interface{}) *UserSession {
	session := &UserSession{}

	if sysID, ok := data["sys_id"].(string); ok {
		session.SysID = sysID
	}
	if userSysID, ok := data["user"].(string); ok {
		session.UserSysID = userSysID
	}
	if sessionID, ok := data["session_id"].(string); ok {
		session.SessionID = sessionID
	}
	if ipAddress, ok := data["ip_address"].(string); ok {
		session.IPAddress = ipAddress
	}
	if userAgent, ok := data["user_agent"].(string); ok {
		session.UserAgent = userAgent
	}
	if active, ok := data["active"].(string); ok {
		session.Active = active == "true"
	}
	if loginType, ok := data["login_type"].(string); ok {
		session.LoginType = loginType
	}
	if device, ok := data["device"].(string); ok {
		session.Device = device
	}
	if application, ok := data["application"].(string); ok {
		session.Application = application
	}
	if idleTime, ok := data["idle_time"].(string); ok {
		if time, err := fmt.Sscanf(idleTime, "%d", &session.IdleTime); err == nil && time == 1 {
			// Successfully parsed
		}
	}
	if timeZone, ok := data["time_zone"].(string); ok {
		session.TimeZone = timeZone
	}

	// Parse timestamps
	if loginTime, ok := data["login_time"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", loginTime); err == nil {
			session.LoginTime = t
		}
	}
	if lastAccessTime, ok := data["last_access_time"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", lastAccessTime); err == nil {
			session.LastAccessTime = t
		}
	}

	return session
}

// Helper method to map raw data to UserPreference struct
func (a *AccessClient) mapDataToUserPreference(data map[string]interface{}) *UserPreference {
	preference := &UserPreference{}

	if sysID, ok := data["sys_id"].(string); ok {
		preference.SysID = sysID
	}
	if userSysID, ok := data["user"].(string); ok {
		preference.UserSysID = userSysID
	}
	if name, ok := data["name"].(string); ok {
		preference.Name = name
	}
	if value, ok := data["value"].(string); ok {
		preference.Value = value
	}
	if prefType, ok := data["type"].(string); ok {
		preference.Type = prefType
	}
	if personal, ok := data["personal"].(string); ok {
		preference.Personal = personal == "true"
	}

	return preference
}
