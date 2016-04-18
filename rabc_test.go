package rbac

import (
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
	_, err := rbacTest.Users().Assign("forum_moderator", 1)
	assert.Nil(t, err)
}

func TestRolesAddPath(t *testing.T) {
	_, err := rbacTest.Roles().AddPath("/admin/test", []string{"admin", "test"})
	assert.Nil(t, err)
}

func TestCheckPermissionOnUser1(t *testing.T) {
	success, err := rbacTest.Check("delete_posts", 1)
	assert.Nil(t, err)
	assert.Equal(t, true, success)
}

func TestHasRole(t *testing.T) {
	success, err := rbacTest.Users().HasRole("forum_moderator", 1)
	assert.Nil(t, err)
	assert.Equal(t, true, success)

	success, err = rbacTest.Users().HasRole("forum_moderatoar", 2)
	assert.Equal(t, ErrTitleNotFound, err)
	assert.Equal(t, false, success)
}
