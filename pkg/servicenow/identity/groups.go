package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// GroupClient handles group management operations
type GroupClient struct {
	client *IdentityClient
}

// NewGroupClient creates a new group client
func (i *IdentityClient) NewGroupClient() *GroupClient {
	return &GroupClient{client: i}
}

// GetGroup retrieves a group by sys_id
func (g *GroupClient) GetGroup(sysID string) (*Group, error) {
	return g.GetGroupWithContext(context.Background(), sysID)
}

// GetGroupWithContext retrieves a group by sys_id with context support
func (g *GroupClient) GetGroupWithContext(ctx context.Context, sysID string) (*Group, error) {
	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "GET", fmt.Sprintf("/table/sys_user_group/%s", escapeIdentityPathSegment(sysID)), nil, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	groupData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for group get: %T", result.Result)
	}

	return g.mapDataToGroup(groupData), nil
}

// GetGroupByName retrieves a group by name
func (g *GroupClient) GetGroupByName(groupName string) (*Group, error) {
	return g.GetGroupByNameWithContext(context.Background(), groupName)
}

// GetGroupByNameWithContext retrieves a group by name with context support
func (g *GroupClient) GetGroupByNameWithContext(ctx context.Context, groupName string) (*Group, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("name=%s", sanitizeEncodedQueryValue(groupName)),
		"sysparm_limit": "1",
	}

	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_group", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get group by name: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for group search: %T", result.Result)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("group not found: %s", groupName)
	}

	groupData, ok := results[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected group data type: %T", results[0])
	}

	return g.mapDataToGroup(groupData), nil
}

// ListGroups retrieves groups based on filter criteria
func (g *GroupClient) ListGroups(filter *GroupFilter) ([]*Group, error) {
	return g.ListGroupsWithContext(context.Background(), filter)
}

// ListGroupsWithContext retrieves groups based on filter criteria with context support
func (g *GroupClient) ListGroupsWithContext(ctx context.Context, filter *GroupFilter) ([]*Group, error) {
	params := g.buildGroupFilterParams(filter)

	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_group", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for group list: %T", result.Result)
	}

	var groups []*Group
	for _, result := range results {
		groupData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		groups = append(groups, g.mapDataToGroup(groupData))
	}

	return groups, nil
}

// CreateGroup creates a new group
func (g *GroupClient) CreateGroup(groupData map[string]interface{}) (*Group, error) {
	return g.CreateGroupWithContext(context.Background(), groupData)
}

// CreateGroupWithContext creates a new group with context support
func (g *GroupClient) CreateGroupWithContext(ctx context.Context, groupData map[string]interface{}) (*Group, error) {
	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "POST", "/table/sys_user_group", groupData, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for group create: %T", result.Result)
	}

	return g.mapDataToGroup(resultData), nil
}

// UpdateGroup updates an existing group
func (g *GroupClient) UpdateGroup(sysID string, updates map[string]interface{}) (*Group, error) {
	return g.UpdateGroupWithContext(context.Background(), sysID, updates)
}

// UpdateGroupWithContext updates an existing group with context support
func (g *GroupClient) UpdateGroupWithContext(ctx context.Context, sysID string, updates map[string]interface{}) (*Group, error) {
	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "PUT", fmt.Sprintf("/table/sys_user_group/%s", escapeIdentityPathSegment(sysID)), updates, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to update group: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for group update: %T", result.Result)
	}

	return g.mapDataToGroup(resultData), nil
}

// DeleteGroup removes a group (sets active = false)
func (g *GroupClient) DeleteGroup(sysID string) error {
	return g.DeleteGroupWithContext(context.Background(), sysID)
}

// DeleteGroupWithContext removes a group with context support
func (g *GroupClient) DeleteGroupWithContext(ctx context.Context, sysID string) error {
	// In ServiceNow, we typically deactivate groups rather than delete them
	updates := map[string]interface{}{
		"active": false,
	}

	_, err := g.UpdateGroupWithContext(ctx, sysID, updates)
	if err != nil {
		return fmt.Errorf("failed to deactivate group: %w", err)
	}

	return nil
}

// AddUserToGroup adds a user to a group
func (g *GroupClient) AddUserToGroup(userSysID, groupSysID string) (*GroupMember, error) {
	return g.AddUserToGroupWithContext(context.Background(), userSysID, groupSysID)
}

// AddUserToGroupWithContext adds a user to a group with context support
func (g *GroupClient) AddUserToGroupWithContext(ctx context.Context, userSysID, groupSysID string) (*GroupMember, error) {
	membershipData := map[string]interface{}{
		"user":  userSysID,
		"group": groupSysID,
	}

	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "POST", "/table/sys_user_grmember", membershipData, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to add user to group: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for group membership: %T", result.Result)
	}

	return g.mapDataToGroupMember(resultData), nil
}

// RemoveUserFromGroup removes a user from a group
func (g *GroupClient) RemoveUserFromGroup(userSysID, groupSysID string) error {
	return g.RemoveUserFromGroupWithContext(context.Background(), userSysID, groupSysID)
}

// RemoveUserFromGroupWithContext removes a user from a group with context support
func (g *GroupClient) RemoveUserFromGroupWithContext(ctx context.Context, userSysID, groupSysID string) error {
	// Find the membership record
	params := map[string]string{
		"sysparm_query": fmt.Sprintf(
			"user=%s^group=%s",
			sanitizeEncodedQueryValue(userSysID),
			sanitizeEncodedQueryValue(groupSysID),
		),
		"sysparm_limit": "1",
	}

	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_grmember", nil, params, &result)
	if err != nil {
		return fmt.Errorf("failed to find group membership: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return fmt.Errorf("unexpected result type for membership search: %T", result.Result)
	}

	if len(results) == 0 {
		return fmt.Errorf("group membership not found")
	}

	membershipData, ok := results[0].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected membership data type: %T", results[0])
	}

	membershipSysID, ok := membershipData["sys_id"].(string)
	if !ok {
		return fmt.Errorf("membership sys_id not found")
	}

	// Delete the membership
	err = g.client.client.RawRequestWithContext(ctx, "DELETE", fmt.Sprintf("/table/sys_user_grmember/%s", escapeIdentityPathSegment(membershipSysID)), nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to remove group membership: %w", err)
	}

	return nil
}

// GetGroupMembers retrieves all members of a group
func (g *GroupClient) GetGroupMembers(groupSysID string) ([]*GroupMember, error) {
	return g.GetGroupMembersWithContext(context.Background(), groupSysID)
}

// GetGroupMembersWithContext retrieves all members of a group with context support
func (g *GroupClient) GetGroupMembersWithContext(ctx context.Context, groupSysID string) ([]*GroupMember, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("group=%s", sanitizeEncodedQueryValue(groupSysID)),
	}

	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_grmember", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for group members: %T", result.Result)
	}

	var members []*GroupMember
	for _, result := range results {
		memberData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		members = append(members, g.mapDataToGroupMember(memberData))
	}

	return members, nil
}

// GetUserGroups retrieves all groups a user is a member of
func (g *GroupClient) GetUserGroups(userSysID string) ([]*GroupMember, error) {
	return g.GetUserGroupsWithContext(context.Background(), userSysID)
}

// GetUserGroupsWithContext retrieves all groups a user is a member of with context support
func (g *GroupClient) GetUserGroupsWithContext(ctx context.Context, userSysID string) ([]*GroupMember, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("user=%s", sanitizeEncodedQueryValue(userSysID)),
	}

	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_grmember", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for user groups: %T", result.Result)
	}

	var memberships []*GroupMember
	for _, result := range results {
		memberData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		memberships = append(memberships, g.mapDataToGroupMember(memberData))
	}

	return memberships, nil
}

// GetGroupHierarchy retrieves the hierarchy of groups including parent-child relationships
func (g *GroupClient) GetGroupHierarchy(groupSysID string) (map[string][]*Group, error) {
	return g.GetGroupHierarchyWithContext(context.Background(), groupSysID)
}

// GetGroupHierarchyWithContext retrieves group hierarchy with context support
func (g *GroupClient) GetGroupHierarchyWithContext(ctx context.Context, groupSysID string) (map[string][]*Group, error) {
	hierarchy := make(map[string][]*Group)
	visited := make(map[string]bool)

	err := g.buildGroupHierarchy(ctx, groupSysID, hierarchy, visited)
	if err != nil {
		return nil, err
	}

	return hierarchy, nil
}

// buildGroupHierarchy recursively builds the group hierarchy
func (g *GroupClient) buildGroupHierarchy(ctx context.Context, groupSysID string, hierarchy map[string][]*Group, visited map[string]bool) error {
	if visited[groupSysID] {
		return nil
	}
	visited[groupSysID] = true

	// Get child groups
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("parent=%s", sanitizeEncodedQueryValue(groupSysID)),
	}

	var result core.Response
	err := g.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_user_group", nil, params, &result)
	if err != nil {
		return fmt.Errorf("failed to get child groups for %s: %w", groupSysID, err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return fmt.Errorf("unexpected result type for child groups: %T", result.Result)
	}

	var childGroups []*Group
	for _, result := range results {
		groupData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		childGroup := g.mapDataToGroup(groupData)
		childGroups = append(childGroups, childGroup)

		// Recursively get children of this child
		err := g.buildGroupHierarchy(ctx, childGroup.SysID, hierarchy, visited)
		if err != nil {
			continue // Continue with other groups if one fails
		}
	}

	hierarchy[groupSysID] = childGroups
	return nil
}

// BulkAddUsersToGroup adds multiple users to a group in one operation
func (g *GroupClient) BulkAddUsersToGroup(userSysIDs []string, groupSysID string) ([]*GroupMember, error) {
	return g.BulkAddUsersToGroupWithContext(context.Background(), userSysIDs, groupSysID)
}

// BulkAddUsersToGroupWithContext adds multiple users to a group with context support
func (g *GroupClient) BulkAddUsersToGroupWithContext(ctx context.Context, userSysIDs []string, groupSysID string) ([]*GroupMember, error) {
	var addedMembers []*GroupMember

	for _, userSysID := range userSysIDs {
		member, err := g.AddUserToGroupWithContext(ctx, userSysID, groupSysID)
		if err != nil {
			// Continue with other users if one fails
			continue
		}
		addedMembers = append(addedMembers, member)
	}

	return addedMembers, nil
}

// BulkRemoveUsersFromGroup removes multiple users from a group
func (g *GroupClient) BulkRemoveUsersFromGroup(userSysIDs []string, groupSysID string) error {
	return g.BulkRemoveUsersFromGroupWithContext(context.Background(), userSysIDs, groupSysID)
}

// BulkRemoveUsersFromGroupWithContext removes multiple users from a group with context support
func (g *GroupClient) BulkRemoveUsersFromGroupWithContext(ctx context.Context, userSysIDs []string, groupSysID string) error {
	for _, userSysID := range userSysIDs {
		err := g.RemoveUserFromGroupWithContext(ctx, userSysID, groupSysID)
		if err != nil {
			// Continue with other users if one fails
			continue
		}
	}

	return nil
}

// Helper method to build group filter parameters
func (g *GroupClient) buildGroupFilterParams(filter *GroupFilter) map[string]string {
	params := make(map[string]string)

	if filter == nil {
		return params
	}

	var queryParts []string

	if filter.Active != nil {
		queryParts = append(queryParts, fmt.Sprintf("active=%t", *filter.Active))
	}
	if filter.Type != "" {
		queryParts = append(queryParts, fmt.Sprintf("type=%s", sanitizeEncodedQueryValue(filter.Type)))
	}
	if filter.Parent != "" {
		queryParts = append(queryParts, fmt.Sprintf("parent=%s", sanitizeEncodedQueryValue(filter.Parent)))
	}
	if filter.Manager != "" {
		queryParts = append(queryParts, fmt.Sprintf("manager=%s", sanitizeEncodedQueryValue(filter.Manager)))
	}
	if filter.Name != "" {
		queryParts = append(queryParts, fmt.Sprintf("nameLIKE%s", sanitizeEncodedQueryValue(filter.Name)))
	}
	if filter.CostCenter != "" {
		queryParts = append(queryParts, fmt.Sprintf("cost_center=%s", sanitizeEncodedQueryValue(filter.CostCenter)))
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

// Helper method to map raw data to Group struct
func (g *GroupClient) mapDataToGroup(data map[string]interface{}) *Group {
	group := &Group{
		Attributes: make(map[string]interface{}),
	}

	if sysID, ok := data["sys_id"].(string); ok {
		group.SysID = sysID
	}
	if name, ok := data["name"].(string); ok {
		group.Name = name
	}
	if description, ok := data["description"].(string); ok {
		group.Description = description
	}
	if groupType, ok := data["type"].(string); ok {
		group.Type = groupType
	}
	if active, ok := data["active"].(string); ok {
		group.Active = active == "true"
	}
	if email, ok := data["email"].(string); ok {
		group.Email = email
	}
	if parent, ok := data["parent"].(string); ok {
		group.Parent = parent
	}
	if manager, ok := data["manager"].(string); ok {
		group.Manager = manager
	}
	if costCenter, ok := data["cost_center"].(string); ok {
		group.CostCenter = costCenter
	}
	if defaultAssignee, ok := data["default_assignee"].(string); ok {
		group.DefaultAssignee = defaultAssignee
	}
	if includeMembers, ok := data["include_members"].(string); ok {
		group.IncludeMembers = includeMembers == "true"
	}
	if points, ok := data["points"].(string); ok {
		if p, err := fmt.Sscanf(points, "%d", &group.Points); err == nil && p == 1 {
			// Successfully parsed
		}
	}
	if source, ok := data["source"].(string); ok {
		group.Source = source
	}
	if createdBy, ok := data["sys_created_by"].(string); ok {
		group.CreatedBy = createdBy
	}
	if updatedBy, ok := data["sys_updated_by"].(string); ok {
		group.UpdatedBy = updatedBy
	}

	// Parse timestamps
	if createdOn, ok := data["sys_created_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", createdOn); err == nil {
			group.CreatedOn = t
		}
	}
	if updatedOn, ok := data["sys_updated_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", updatedOn); err == nil {
			group.UpdatedOn = t
		}
	}

	// Store any additional attributes
	standardFields := map[string]bool{
		"sys_id": true, "name": true, "description": true, "type": true,
		"active": true, "email": true, "parent": true, "manager": true,
		"cost_center": true, "default_assignee": true, "include_members": true,
		"points": true, "source": true, "sys_created_by": true, "sys_updated_by": true,
		"sys_created_on": true, "sys_updated_on": true,
	}

	for key, value := range data {
		if !standardFields[key] {
			group.Attributes[key] = value
		}
	}

	return group
}

// Helper method to map raw data to GroupMember struct
func (g *GroupClient) mapDataToGroupMember(data map[string]interface{}) *GroupMember {
	member := &GroupMember{}

	if sysID, ok := data["sys_id"].(string); ok {
		member.SysID = sysID
	}
	if userSysID, ok := data["user"].(string); ok {
		member.UserSysID = userSysID
	}
	if groupSysID, ok := data["group"].(string); ok {
		member.GroupSysID = groupSysID
	}
	if addedBy, ok := data["sys_created_by"].(string); ok {
		member.AddedBy = addedBy
	}

	// Parse timestamps
	if addedOn, ok := data["sys_created_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", addedOn); err == nil {
			member.AddedOn = t
		}
	}

	return member
}
