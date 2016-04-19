package rbac

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

var rbacTest Rbac
var mu sync.Mutex

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
	var err error
	_, err = rbacTest.Roles().AddPath("/my/path", nil)
	assert.Nil(t, err)

	pathId, err := rbacTest.Roles().GetRoleId("/my/path")
	assert.Nil(t, err)

	path, err := rbacTest.Roles().GetPath(pathId)
	assert.Nil(t, err)
	assert.Equal(t, "/my/path", path)

}

func TestRemoveRoleRecursive(t *testing.T) {
	var err error
	_, err = rbacTest.Roles().Add("forum_moderator", "User can moderate forums", 0)
	assert.Nil(t, err)

	permissionId, err := rbacTest.Permissions().Add("edit_posts", "User can edit posts", 0)
	assert.Nil(t, err)

	_, err = rbacTest.Assign("forum_moderator", "edit_posts")
	assert.Nil(t, err)

	permissions, err := rbacTest.Roles().Permissions("forum_moderator")
	assert.Nil(t, err)

	err = rbacTest.Unassign("forum_moderator", "delete_posts")
	assert.Nil(t, err)

	err = rbacTest.Unassign("forum_moderator", "edit_posts")
	assert.Nil(t, err)

	permissions, err = rbacTest.Roles().Permissions("forum_moderator")
	assert.Nil(t, err)
	assert.Equal(t, 0, len(permissions))

	_, err = rbacTest.Assign("forum_moderator", permissionId)
	assert.Nil(t, err)

	err = rbacTest.Roles().Remove("forum_moderator", true)
	assert.Nil(t, err)
}

func TestDepth(t *testing.T) {
	_, err := rbacTest.Roles().AddPath("/my1/testpath/test1", nil)
	assert.Nil(t, err)

	pathId, err := rbacTest.Roles().GetRoleId("/my1/testpath/test1")

	depth, err := rbacTest.Roles().Depth(pathId)
	assert.Nil(t, err)
	assert.Equal(t, 3, depth)
}

func TestEdit(t *testing.T) {

	roleId, err := rbacTest.Roles().GetRoleId("forum_moderator")
	assert.Nil(t, err)

	title, err := rbacTest.Roles().GetTitle(roleId)
	assert.Nil(t, err)
	assert.Equal(t, "forum_moderator", title)

	err = rbacTest.Roles().Edit(roleId, "forum_moderator1", "")
	title, err = rbacTest.Roles().GetTitle(roleId)
	assert.Nil(t, err)
	assert.Equal(t, "forum_moderator1", title)
}

func TestParentId(t *testing.T) {
	roleId, err := rbacTest.Roles().GetRoleId("/my1/testpath/test1")
	assert.Nil(t, err)

	_, err = rbacTest.Roles().Add("test123", "", roleId)
	newRoleId, err := rbacTest.Roles().GetRoleId("/my1/testpath/test1/test123")

	parentId, err := rbacTest.Roles().ParentNode(newRoleId)
	assert.Nil(t, err)
	assert.Equal(t, roleId, parentId)

}

func TestReturnId(t *testing.T) {
	roleId, err := rbacTest.Roles().GetRoleId("my1")
	assert.Nil(t, err)

	returnId, err := rbacTest.Roles().ReturnId("my1")
	assert.Nil(t, err)

	assert.Equal(t, roleId, returnId)
}

func TestDescendants(t *testing.T) {
	roleId, err := rbacTest.Roles().GetRoleId("my1")
	assert.Nil(t, err)
	res, err := rbacTest.Roles().Descendants(false, roleId)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(res))
}

func TestChildren(t *testing.T) {
	roleId, err := rbacTest.Roles().GetRoleId("my1")
	assert.Nil(t, err)
	res, err := rbacTest.Roles().Children(roleId)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(res))
}
