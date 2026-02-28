package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// RoleClient handles role management operations
type RoleClient struct {
	client *IdentityClient
}

// NewRoleClient creates a new role client
func (i *IdentityClient) NewRoleClient() *RoleClient {
	return &RoleClient{client: i}
}

// GetRole retrieves a role by sys_id
func (r *RoleClient) GetRole(sysID string) (*Role, error) {
	return r.GetRoleWithContext(context.Background(), sysID)
}

// GetRoleWithContext retrieves a role by sys_id with context support
func (r *RoleClient) GetRoleWithContext(ctx context.Context, sysID string) (*Role, error) {
	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", fmt.Sprintf("/table/sys_user_role/%s", sysID), nil, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	roleData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for role get: %T", result.Result)
	}

	return r.mapDataToRole(roleData), nil
}

// GetRoleByName retrieves a role by name
func (r *RoleClient) GetRoleByName(roleName string) (*Role, error) {
	return r.GetRoleByNameWithContext(context.Background(), roleName)
}

// GetRoleByNameWithContext retrieves a role by name with context support
func (r *RoleClient) GetRoleByNameWithContext(ctx context.Context, roleName string) (*Role, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("name=%s", sanitizeEncodedQueryValue(roleName)),
		"sysparm_limit": "1",
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_role", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for role search: %T", result.Result)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("role not found: %s", roleName)
	}

	roleData, ok := results[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected role data type: %T", results[0])
	}

	return r.mapDataToRole(roleData), nil
}

// ListRoles retrieves roles based on filter criteria
func (r *RoleClient) ListRoles(filter *RoleFilter) ([]*Role, error) {
	return r.ListRolesWithContext(context.Background(), filter)
}

// ListRolesWithContext retrieves roles based on filter criteria with context support
func (r *RoleClient) ListRolesWithContext(ctx context.Context, filter *RoleFilter) ([]*Role, error) {
	params := r.buildRoleFilterParams(filter)

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_role", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for role list: %T", result.Result)
	}

	var roles []*Role
	for _, result := range results {
		roleData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		roles = append(roles, r.mapDataToRole(roleData))
	}

	return roles, nil
}

// CreateRole creates a new role
func (r *RoleClient) CreateRole(roleData map[string]interface{}) (*Role, error) {
	return r.CreateRoleWithContext(context.Background(), roleData)
}

// CreateRoleWithContext creates a new role with context support
func (r *RoleClient) CreateRoleWithContext(ctx context.Context, roleData map[string]interface{}) (*Role, error) {
	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "POST", "/table/sys_user_role", roleData, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for role create: %T", result.Result)
	}

	return r.mapDataToRole(resultData), nil
}

// UpdateRole updates an existing role
func (r *RoleClient) UpdateRole(sysID string, updates map[string]interface{}) (*Role, error) {
	return r.UpdateRoleWithContext(context.Background(), sysID, updates)
}

// UpdateRoleWithContext updates an existing role with context support
func (r *RoleClient) UpdateRoleWithContext(ctx context.Context, sysID string, updates map[string]interface{}) (*Role, error) {
	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "PUT", fmt.Sprintf("/table/sys_user_role/%s", sysID), updates, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for role update: %T", result.Result)
	}

	return r.mapDataToRole(resultData), nil
}

// DeleteRole removes a role (sets active = false)
func (r *RoleClient) DeleteRole(sysID string) error {
	return r.DeleteRoleWithContext(context.Background(), sysID)
}

// DeleteRoleWithContext removes a role with context support
func (r *RoleClient) DeleteRoleWithContext(ctx context.Context, sysID string) error {
	// In ServiceNow, we typically deactivate roles rather than delete them
	updates := map[string]interface{}{
		"active": "false",
	}

	_, err := r.UpdateRoleWithContext(ctx, sysID, updates)
	if err != nil {
		return fmt.Errorf("failed to deactivate role: %w", err)
	}

	return nil
}

// AssignRoleToUser assigns a role to a user
func (r *RoleClient) AssignRoleToUser(userSysID, roleSysID string) (*UserRole, error) {
	return r.AssignRoleToUserWithContext(context.Background(), userSysID, roleSysID)
}

// AssignRoleToUserWithContext assigns a role to a user with context support
func (r *RoleClient) AssignRoleToUserWithContext(ctx context.Context, userSysID, roleSysID string) (*UserRole, error) {
	assignmentData := map[string]interface{}{
		"user": userSysID,
		"role": roleSysID,
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "POST", "/table/sys_user_has_role", assignmentData, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to assign role to user: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for role assignment: %T", result.Result)
	}

	return r.mapDataToUserRole(resultData), nil
}

// RemoveRoleFromUser removes a role from a user
func (r *RoleClient) RemoveRoleFromUser(userSysID, roleSysID string) error {
	return r.RemoveRoleFromUserWithContext(context.Background(), userSysID, roleSysID)
}

// RemoveRoleFromUserWithContext removes a role from a user with context support
func (r *RoleClient) RemoveRoleFromUserWithContext(ctx context.Context, userSysID, roleSysID string) error {
	// Find the assignment record
	params := map[string]string{
		"sysparm_query": fmt.Sprintf(
			"user=%s^role=%s",
			sanitizeEncodedQueryValue(userSysID),
			sanitizeEncodedQueryValue(roleSysID),
		),
		"sysparm_limit": "1",
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_has_role", nil, params, &result)
	if err != nil {
		return fmt.Errorf("failed to find role assignment: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return fmt.Errorf("unexpected result type for role assignment search: %T", result.Result)
	}

	if len(results) == 0 {
		return fmt.Errorf("role assignment not found")
	}

	assignmentData, ok := results[0].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected assignment data type: %T", results[0])
	}

	assignmentSysID, ok := assignmentData["sys_id"].(string)
	if !ok {
		return fmt.Errorf("assignment sys_id not found")
	}

	// Delete the assignment
	err = r.client.client.RawRequestWithContext(ctx, "DELETE", fmt.Sprintf("/table/sys_user_has_role/%s", assignmentSysID), nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to remove role assignment: %w", err)
	}

	return nil
}

// GetUserRoles retrieves all roles assigned to a user
func (r *RoleClient) GetUserRoles(userSysID string) ([]*UserRole, error) {
	return r.GetUserRolesWithContext(context.Background(), userSysID)
}

// GetUserRolesWithContext retrieves all roles assigned to a user with context support
func (r *RoleClient) GetUserRolesWithContext(ctx context.Context, userSysID string) ([]*UserRole, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("user=%s", sanitizeEncodedQueryValue(userSysID)),
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_has_role", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for user roles: %T", result.Result)
	}

	var userRoles []*UserRole
	for _, result := range results {
		roleData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		userRoles = append(userRoles, r.mapDataToUserRole(roleData))
	}

	return userRoles, nil
}

// GetRoleUsers retrieves all users assigned to a role
func (r *RoleClient) GetRoleUsers(roleSysID string) ([]*UserRole, error) {
	return r.GetRoleUsersWithContext(context.Background(), roleSysID)
}

// GetRoleUsersWithContext retrieves all users assigned to a role with context support
func (r *RoleClient) GetRoleUsersWithContext(ctx context.Context, roleSysID string) ([]*UserRole, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("role=%s", sanitizeEncodedQueryValue(roleSysID)),
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_has_role", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for role users: %T", result.Result)
	}

	var userRoles []*UserRole
	for _, result := range results {
		roleData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		userRoles = append(userRoles, r.mapDataToUserRole(roleData))
	}

	return userRoles, nil
}

// GetRoleHierarchy retrieves the hierarchy of roles including included roles
func (r *RoleClient) GetRoleHierarchy(roleSysID string) (map[string][]*Role, error) {
	return r.GetRoleHierarchyWithContext(context.Background(), roleSysID)
}

// GetRoleHierarchyWithContext retrieves role hierarchy with context support
func (r *RoleClient) GetRoleHierarchyWithContext(ctx context.Context, roleSysID string) (map[string][]*Role, error) {
	hierarchy := make(map[string][]*Role)
	visited := make(map[string]bool)

	err := r.buildRoleHierarchy(ctx, roleSysID, hierarchy, visited)
	if err != nil {
		return nil, err
	}

	return hierarchy, nil
}

// buildRoleHierarchy recursively builds the role hierarchy
func (r *RoleClient) buildRoleHierarchy(ctx context.Context, roleSysID string, hierarchy map[string][]*Role, visited map[string]bool) error {
	if visited[roleSysID] {
		return nil
	}
	visited[roleSysID] = true

	// Get roles that include this role
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("contains_roles=%s", sanitizeEncodedQueryValue(roleSysID)),
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_role_contains", nil, params, &result)
	if err != nil {
		return fmt.Errorf("failed to get role inclusions for %s: %w", roleSysID, err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return fmt.Errorf("unexpected result type for role inclusions: %T", result.Result)
	}

	var includedRoles []*Role
	for _, result := range results {
		inclusionData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		if parentRoleSysID, ok := inclusionData["role"].(string); ok {
			parentRole, err := r.GetRoleWithContext(ctx, parentRoleSysID)
			if err != nil {
				continue
			}
			includedRoles = append(includedRoles, parentRole)

			// Recursively get parents of this parent
			err = r.buildRoleHierarchy(ctx, parentRoleSysID, hierarchy, visited)
			if err != nil {
				continue
			}
		}
	}

	hierarchy[roleSysID] = includedRoles
	return nil
}

// Helper method to build role filter parameters
func (r *RoleClient) buildRoleFilterParams(filter *RoleFilter) map[string]string {
	params := make(map[string]string)

	if filter == nil {
		return params
	}

	var queryParts []string

	if filter.Active != nil {
		queryParts = append(queryParts, fmt.Sprintf("active=%t", *filter.Active))
	}
	if filter.Assignable != nil {
		queryParts = append(queryParts, fmt.Sprintf("assignable_by=%t", *filter.Assignable))
	}
	if filter.ElevatedPrivilege != nil {
		queryParts = append(queryParts, fmt.Sprintf("elevated_privilege=%t", *filter.ElevatedPrivilege))
	}
	if filter.Application != "" {
		queryParts = append(queryParts, fmt.Sprintf("application=%s", sanitizeEncodedQueryValue(filter.Application)))
	}
	if filter.Name != "" {
		queryParts = append(queryParts, fmt.Sprintf("nameLIKE%s", sanitizeEncodedQueryValue(filter.Name)))
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

// Helper method to map raw data to Role struct
func (r *RoleClient) mapDataToRole(data map[string]interface{}) *Role {
	role := &Role{
		Attributes: make(map[string]interface{}),
	}

	if sysID, ok := data["sys_id"].(string); ok {
		role.SysID = sysID
	}
	if name, ok := data["name"].(string); ok {
		role.Name = name
	}
	if description, ok := data["description"].(string); ok {
		role.Description = description
	}
	if active, ok := data["active"].(string); ok {
		role.Active = active == "true"
	}
	if assignable, ok := data["assignable_by"].(string); ok {
		role.Assignable = assignable == "true"
	}
	if canDelegate, ok := data["can_delegate"].(string); ok {
		role.CanDelegate = canDelegate == "true"
	}
	if elevatedPrivilege, ok := data["elevated_privilege"].(string); ok {
		role.ElevatedPrivilege = elevatedPrivilege == "true"
	}
	if requiresSubscription, ok := data["requires_subscription"].(string); ok {
		role.RequiresSubscription = requiresSubscription
	}
	if scoped, ok := data["scoped"].(string); ok {
		role.Scoped = scoped == "true"
	}
	if application, ok := data["application"].(string); ok {
		role.ApplicationScope = application
	}
	if suffix, ok := data["suffix"].(string); ok {
		role.Suffix = suffix
	}
	if grantsAdmin, ok := data["grants_admin"].(string); ok {
		role.GrantsAdmin = grantsAdmin == "true"
	}
	if createdBy, ok := data["sys_created_by"].(string); ok {
		role.CreatedBy = createdBy
	}
	if updatedBy, ok := data["sys_updated_by"].(string); ok {
		role.UpdatedBy = updatedBy
	}

	// Parse timestamps
	if createdOn, ok := data["sys_created_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", createdOn); err == nil {
			role.CreatedOn = t
		}
	}
	if updatedOn, ok := data["sys_updated_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", updatedOn); err == nil {
			role.UpdatedOn = t
		}
	}

	// Store any additional attributes
	standardFields := map[string]bool{
		"sys_id": true, "name": true, "description": true, "active": true,
		"assignable_by": true, "can_delegate": true, "elevated_privilege": true,
		"requires_subscription": true, "scoped": true, "application": true,
		"suffix": true, "grants_admin": true, "sys_created_by": true,
		"sys_updated_by": true, "sys_created_on": true, "sys_updated_on": true,
	}

	for key, value := range data {
		if !standardFields[key] {
			role.Attributes[key] = value
		}
	}

	return role
}

// Helper method to map raw data to UserRole struct
func (r *RoleClient) mapDataToUserRole(data map[string]interface{}) *UserRole {
	userRole := &UserRole{}

	if sysID, ok := data["sys_id"].(string); ok {
		userRole.SysID = sysID
	}
	if userSysID, ok := data["user"].(string); ok {
		userRole.UserSysID = userSysID
	}
	if roleSysID, ok := data["role"].(string); ok {
		userRole.RoleSysID = roleSysID
	}
	if granted, ok := data["granted_by"].(string); ok {
		userRole.Granted = granted
	}
	if state, ok := data["state"].(string); ok {
		userRole.State = state
	}
	if inherited, ok := data["inherited"].(string); ok {
		userRole.Inherited = inherited == "true"
	}

	// Parse timestamps
	if grantedOn, ok := data["sys_created_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", grantedOn); err == nil {
			userRole.GrantedOn = t
		}
	}

	return userRole
}
