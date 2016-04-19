package gorbac

import (
	"errors"
	"fmt"
)

//type RoleManager interface {
//Add(title string, description string, parentId int64) (int64, error)
//AddPath(path string, descriptions []string) (int64, error)

//Assign(role Role, permission Permission) (int64, error)
//Count() (int64, error)
//Depth(id int64) (int64, error)
//Descendants(absolute bool, id int64) ([]path, error)
//Edit(id int64, title, description string) error
//TitleId(title string) (int64, error)

//Unassign(role Role, permission Permission) error
//Children(id int64) ([]path, error)

//ReturnId(entity string) (int64, error)
//ParentNode(id int64) (int64, error)

//Reset(ensure bool) error
//ResetAssignments(ensure bool) error

//GetDescription(Id int64) (string, error)
//GetTitle(id int64) (string, error)
//GetPath(id int64) (string, error)

//HasPermission(role Role, permission Permission) (bool, error)
//Permissions(role Role) (Permissions, error)
//UnassignPermissions(role Role) error
//UnassignUsers(role Role) error
//Remove(role Role, recursive bool) error

//GetRoleId(role Role) (int64, error)
//}

type Roles struct {
	rbac   *Rbac
	entity entityInternal
	table  string
}

// Role can be Id, Title or Path
type Role interface{}

type role struct {
	Id          int64
	Title       string
	Description string
}

var ErrRowRequired = errors.New("role not found")

func newRoleManager(r *Rbac) *Roles {
	var Roles = new(Roles)
	Roles.table = "roles"
	Roles.rbac = r
	Roles.entity = &entity{rbac: r, entityHolder: Roles}
	return Roles
}

func (r Roles) Assign(role Role, permission Permission) (int64, error) {
	return r.entity.assign(role, permission)
}

func (r Roles) Unassign(role Role, permission Permission) error {
	return r.entity.unassign(role, permission)
}

func (r Roles) HasPermission(role Role, permission Permission) (bool, error) {
	var err error
	var roleId, permissionId int64

	roleId, err = r.GetRoleId(role)
	if err != nil {
		return false, err
	}

	permissionId, err = r.rbac.Permissions().GetPermissionId(permission)
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
	err = r.rbac.db.QueryRow(query, roleId, roleId, permissionId).Scan(&result)
	if err != nil {
		return false, err
	}

	if result > 0 {
		return true, nil
	}

	return false, nil
}

func (r Roles) Remove(role Role, recursive bool) error {
	var err error
	var roleId int64

	roleId, err = r.GetRoleId(role)
	if err != nil {
		return err
	}

	r.UnassignPermissions(role)
	r.UnassignUsers(role)

	if recursive {
		r.entity.deleteSubtreeConditional(roleId)
	} else {
		r.entity.deleteConditional(roleId)
	}

	return nil
}

func (r Roles) Add(title string, description string, parentId int64) (int64, error) {
	return r.entity.add(title, description, parentId)
}

func (r Roles) AddPath(path string, description []string) (int64, error) {
	return r.entity.addPath(path, description)
}

func (r Roles) TitleId(title string) (int64, error) {
	return r.entity.titleId(title)
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

func (r Roles) Permissions(role Role) ([]permission, error) {
	var roleId int64
	var err error

	roleId, err = r.rbac.Roles().GetRoleId(role)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`
	SELECT 
		TP.ID, TP.Title, TP.Description 
	FROM permissions AS TP
	LEFT JOIN role_permissions AS TR ON (TR.permission_id=TP.ID)
	WHERE role_id=? ORDER BY TP.ID`)

	rows, err := r.rbac.db.Query(query, roleId)
	if err != nil {
		return nil, err
	}

	var permissions []permission
	for rows.Next() {
		var permission permission
		err := rows.Scan(&permission.Id, &permission.Title, &permission.Description)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil

}

func (r Roles) UnassignPermissions(role Role) error {
	var err error
	var roleId int64

	roleId, err = r.rbac.Roles().GetRoleId(role)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("DELETE FROM role_permissions WHERE role_id=?")
	_, err = r.rbac.db.Exec(query, roleId)

	if err != nil {
		return err
	}

	return nil
}

func (r Roles) UnassignUsers(role Role) error {
	var err error
	var roleId int64

	roleId, err = r.rbac.Roles().GetRoleId(role)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("DELETE FROM user_roles WHERE role_id=?")
	_, err = r.rbac.db.Exec(query, roleId)

	if err != nil {
		return err
	}

	return nil
}

func (r Roles) GetRoleId(role Role) (int64, error) {
	var roleId int64
	var err error
	if _, ok := role.(int64); ok {
		roleId = role.(int64)
	} else if _, ok := role.(string); ok {

		if role.(string)[:1] == "/" {
			roleId, err = r.entity.pathId(role.(string))
			if err != nil {
				return 0, err
			}
		} else {
			roleId, err = r.entity.titleId(role.(string))

			if err != nil {
				return 0, err
			}
		}
	}

	return roleId, nil
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

func (r Roles) ReturnId(entity string) (int64, error) {
	return r.entity.returnId(entity)
}
func (r Roles) Descendants(absolute bool, id int64) ([]path, error) {
	return r.entity.descendants(absolute, id)
}

func (r Roles) Children(id int64) ([]path, error) {
	return r.entity.children(id)
}
