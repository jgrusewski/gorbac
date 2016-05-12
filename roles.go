package gorbac

import (
	"errors"
	"fmt"
)

type Roles struct {
	rbac   *Rbac
	entity entityInternal
	table  string
}

// Role can be ID, Title or Path
type RoleInterface interface{}

type Role struct {
	ID          int64
	Title       string
	Description string
}

// Error messages for Roles
var (
	ErrRowRequired = errors.New("role cannot be nil")
)

func newRoleManager(r *Rbac) *Roles {
	var Roles = new(Roles)
	Roles.table = "roles"
	Roles.rbac = r
	Roles.entity = &entity{rbac: r, entityHolder: Roles}
	return Roles
}

// Assign a role to a permission (or vice-verse).
// Returns true if successful, false if association already exists.
func (r Roles) Assign(role RoleInterface, permission PermissionInterface) (int64, error) {
	return r.entity.assign(role, permission)
}

// Unassign a Role-Permission relation.
func (r Roles) Unassign(role RoleInterface, permission PermissionInterface) error {
	return r.entity.unassign(role, permission)
}

// HasPermission checks to see if a Role has a Permission or not.
func (r Roles) HasPermission(role RoleInterface, permission PermissionInterface) (bool, error) {
	var err error
	var roleID, permissionID int64

	roleID, err = r.GetRoleID(role)
	if err != nil {
		return false, err
	}

	permissionID, err = r.rbac.Permissions().GetPermissionID(permission)
	if err != nil {
		return false, err
	}

	query := fmt.Sprintf(`
		SELECT COUNT(*) AS Result
		FROM role_permissions AS TRel
		JOIN permissions AS TP ON ( TP.ID= TRel.permission_id)
		JOIN roles AS TR ON ( TR.ID = TRel.role_id)
		WHERE TR.Lft BETWEEN
			(SELECT Lft FROM roles WHERE ID=?)
			AND
			(SELECT Rght FROM roles WHERE ID=?)

			/* the above section means any row that is a descendants of our role (if descendant roles have some permission, then our role has it two) */

			AND TP.ID IN (
				SELECT parent.ID
				FROM 
				permissions AS node,
				permissions AS parent
			WHERE node.Lft BETWEEN parent.Lft AND parent.Rght
			AND ( node.ID=? )
			ORDER BY parent.Lft
		);
	`)

	var result int64
	err = r.rbac.db.QueryRow(query, roleID, roleID, permissionID).Scan(&result)
	if err != nil {
		return false, err
	}

	if result > 0 {
		return true, nil
	}

	return false, nil
}

// Remove Roles from system.
// If set to true, all descendants of the Permission will also be removed.
func (r Roles) Remove(role RoleInterface, recursive bool) error {
	var err error
	var roleID int64

	roleID, err = r.GetRoleID(role)
	if err != nil {
		return err
	}

	r.UnassignPermissions(role)
	r.UnassignUsers(role)

	if recursive {
		r.entity.deleteSubtreeConditional(roleID)
	} else {
		r.entity.deleteConditional(roleID)
	}

	return nil
}

func (r Roles) Add(title string, description string, parentID int64) (int64, error) {
	return r.entity.add(title, description, parentID)
}

func (r Roles) AddPath(path string, description []string) (int64, error) {
	return r.entity.addPath(path, description)
}

func (r Roles) TitleID(title string) (int64, error) {
	return r.entity.titleID(title)
}

func (r Roles) Reset(ensure bool) error {
	return r.entity.reset(ensure)
}

func (r Roles) getTable() string {
	return r.table
}

func (r Roles) ResetAssignments(ensure bool) error {
	return r.entity.resetAssignments(ensure)
}

func (r Roles) Permissions(role RoleInterface) ([]permission, error) {
	var roleID int64
	var err error

	roleID, err = r.rbac.Roles().GetRoleID(role)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`
	SELECT 
		TP.ID, TP.Title, TP.Description 
	FROM permissions AS TP
	LEFT JOIN role_permissions AS TR ON (TR.permission_id=TP.ID)
	WHERE role_id=? ORDER BY TP.ID`)

	rows, err := r.rbac.db.Query(query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []permission
	for rows.Next() {
		var permission permission
		err := rows.Scan(&permission.ID, &permission.Title, &permission.Description)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil

}

func (r Roles) UnassignPermissions(role RoleInterface) error {
	var err error
	var roleID int64

	roleID, err = r.rbac.Roles().GetRoleID(role)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("DELETE FROM role_permissions WHERE role_id=?")
	_, err = r.rbac.db.Exec(query, roleID)

	if err != nil {
		return err
	}

	return nil
}

func (r Roles) UnassignUsers(role RoleInterface) error {
	var err error
	var roleID int64

	roleID, err = r.rbac.Roles().GetRoleID(role)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("DELETE FROM user_roles WHERE role_id=?")
	_, err = r.rbac.db.Exec(query, roleID)

	if err != nil {
		return err
	}

	return nil
}

func (r Roles) GetRoleID(role RoleInterface) (int64, error) {
	var roleID int64
	var err error
	if _, ok := role.(int64); ok {
		roleID = role.(int64)
	} else if _, ok := role.(string); ok {

		if role.(string)[:1] == "/" {
			roleID, err = r.entity.pathID(role.(string))
			if err != nil {
				return 0, err
			}
		} else {
			roleID, err = r.entity.titleID(role.(string))

			if err != nil {
				return 0, err
			}
		}
	}

	return roleID, nil
}

func (r Roles) Count() (int64, error) {
	return r.entity.count()
}
func (r Roles) GetDescription(id int64) (string, error) {
	return r.entity.getTitle(id)
}

func (r Roles) GetTitle(id int64) (string, error) {
	return r.entity.getTitle(id)
}

func (r Roles) GetPath(id int64) (string, error) {
	return r.entity.getPath(id)
}

func (r Roles) Depth(id int64) (int64, error) {
	return r.entity.depth(id)
}

func (r Roles) Edit(id int64, title, description string) error {
	return r.entity.edit(id, title, description)
}

func (r Roles) ParentNode(id int64) (int64, error) {
	return r.entity.parentNode(id)
}

func (r Roles) ReturnID(entity string) (int64, error) {
	return r.entity.returnID(entity)
}

// Descendants returns descendants of an Entity, with their depths in integer.
func (r Roles) Descendants(absolute bool, id int64) ([]path, error) {
	return r.entity.descendants(absolute, id)
}

// Children returns children of an Entity.
func (r Roles) Children(id int64) ([]path, error) {
	return r.entity.children(id)
}
