package rbac

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var rbacTest Rbac

func TestMain(m *testing.M) {
	rbacTest = New(&Config{Name: "smartident", Username: "root", Password: "pass", Host: "localhost", Port: 3306})
	rbacTest.Reset(true)

	os.Exit(m.Run())
}

func TestCreatePermission(t *testing.T) {
	_, err := rbacTest.Permissions().Add("delete_posts", "Can delete forum posts", 0)
	assert.Nil(t, err)
}

func TestCreateRole(t *testing.T) {
	_, err := rbacTest.Roles().Add("forum_moderator", "User can moderate forums", 0)
	assert.Nil(t, err)
}

func TestAssignPermissionToRole(t *testing.T) {
	_, err := rbacTest.Assign("forum_moderator", "delete_posts")
	assert.Nil(t, err)

}

func TestAssignRoleToUser(t *testing.T) {
	_, err := rbacTest.Users().Assign("forum_moderator", 105)
	assert.Nil(t, err)
}

func TestHasRoleSuccess(t *testing.T) {
	success, err := rbacTest.Users().HasRole("forum_moderator", 105)
	assert.Nil(t, err)
	assert.Equal(t, true, success)
}

func TestHasRoleFailure(t *testing.T) {
	success, err := rbacTest.Users().HasRole("forum_moderator", 106)
	assert.Nil(t, err)
	assert.Equal(t, false, success)
}

func TestRolesAddPath(t *testing.T) {
	path, err := rbacTest.Roles().AddPath("/admin/test", []string{"admin", "test"})
	assert.Nil(t, err)
	assert.NotEqual(t, 0, path)
}

func TestCheckPermissionOnUser1(t *testing.T) {
	success, err := rbacTest.Check("delete_posts", 105)
	assert.Nil(t, err)
	assert.Equal(t, true, success)
}

func TestUnassignRoleFromUser(t *testing.T) {
	err := rbacTest.Users().Unassign("forum_moderator", 105)
	assert.Nil(t, err)

	success, err := rbacTest.Users().HasRole("forum_moderator", 105)
	assert.Nil(t, err)
	assert.Equal(t, false, success)
}

func TestAllRoles(t *testing.T) {
	_, err := rbacTest.Users().Assign("forum_moderator", 105)
	assert.Nil(t, err)

	roles, err := rbacTest.Users().AllRoles(105)
	assert.Nil(t, err)

	assert.Equal(t, len(roles), 1)

	result, err := rbacTest.Users().RoleCount(105)
	assert.Nil(t, err)

	assert.Equal(t, 1, result)
}

func TestRolePermissions(t *testing.T) {
	result, err := rbacTest.Roles().Permissions("forum_moderator")
	assert.Nil(t, err)

	assert.Equal(t, 1, len(result))
}

func TestRoleHasPermission(t *testing.T) {
	success, err := rbacTest.Roles().HasPermission("forum_moderator", "delete_posts")
	assert.Nil(t, err)

	assert.Equal(t, true, success)
}

func TestRemoveRole(t *testing.T) {
	var err error

	permissionId, err := rbacTest.Permissions().Add("edit_posts", "User can edit posts", 0)
	assert.Nil(t, err)

	_, err = rbacTest.Assign("forum_moderator", permissionId)
	assert.Nil(t, err)

	err = rbacTest.Roles().Remove("forum_moderator", false)
	assert.Nil(t, err)
}
func TestGetPath(t *testing.T) {
	path, err := rbacTest.Roles().GetPath(4)
	assert.Nil(t, err)
	assert.Equal(t, "/admin/test", path)

}

func TestRemoveRoleRecursive(t *testing.T) {
	var err error
	_, err = rbacTest.Roles().Add("forum_moderator", "User can moderate forums", 0)
	assert.Nil(t, err)

	_, err = rbacTest.Assign("forum_moderator", "delete_posts")
	assert.Nil(t, err)

	permissionId, err := rbacTest.Permissions().Add("edit_posts", "User can edit posts", 0)
	assert.Nil(t, err)

	_, err = rbacTest.Assign("forum_moderator", permissionId)
	assert.Nil(t, err)

	err = rbacTest.Roles().Remove("forum_moderator", true)
	assert.Nil(t, err)
}

func TestDepth(t *testing.T) {
	depth, err := rbacTest.Roles().Depth(4)
	assert.Nil(t, err)
	fmt.Println(depth)
}
