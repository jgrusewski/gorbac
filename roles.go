package rbac

import (
	"errors"
	"fmt"
)

type RoleManager interface {
	Entity

	HasPermission(role Role, permission Permission) (bool, error)
	Permissions(role Role) (Permissions, error)
	UnassignPermissions(role Role) error
	UnassignUsers(role Role) error
	Remove(role Role, recursive bool) error

	getRoleId(role Role) (int64, error)
}

type roleManager struct {
	rbac   *rbac
	entity *entity
	table  string
}

type Role interface{}
type role struct {
	Id          int64
	Title       string
	Description string
}

type Roles []role

var ErrRowRequired = errors.New("role not found")

func NewRoleManager(r *rbac) RoleManager {
	var roleManager = new(roleManager)
	roleManager.table = "roles"
	roleManager.rbac = r
	roleManager.entity = &entity{rbac: r, entityHolder: roleManager}
	return roleManager
}

func (r roleManager) Assign(role Role, permission Permission) (int64, error) {
	return r.entity.Assign(role, permission)
}

func (r roleManager) HasPermission(role Role, permission Permission) (bool, error) {
	var err error
	var roleId, permissionId int64

	roleId, err = r.getRoleId(role)
	if err != nil {
		return false, err
	}

	permissionId, err = r.rbac.Permissions().getPermissionId(permission)
	if err != nil {
		return false, err
	}

	query := fmt.Sprintf(`
		SELECT COUNT(*) AS Result
		FROM rolepermissions AS TRel
		JOIN permissions AS TP ON ( TP.ID= TRel.PermissionID)
		JOIN roles AS TR ON ( TR.ID = TRel.RoleID)
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

func (r roleManager) Remove(role Role, recursive bool) error {
	var err error
	var roleId int64

	roleId, err = r.getRoleId(role)
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

func (r roleManager) Add(title string, description string, parentId int64) (int64, error) {
	return r.entity.Add(title, description, parentId)
}

func (r roleManager) AddPath(path string, description []string) (int, error) {
	return r.entity.AddPath(path, description)
}

func (r roleManager) titleId(title string) (int64, error) {
	return r.entity.titleId(title)
}

func (r roleManager) reset(ensure bool) error {
	return r.entity.reset(ensure)
}

func (r roleManager) getTable() string {
	return r.table
}

func (r roleManager) resetAssignments(ensure bool) error {
	return r.entity.resetAssignments(ensure)
}

func (r roleManager) Permissions(role Role) (Permissions, error) {
	var roleId int64
	var err error

	roleId, err = r.rbac.Roles().getRoleId(role)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`
	SELECT 
		TP.ID, TP.Title, TP.Description 
	FROM permissions AS TP
	LEFT JOIN rolepermissions AS TR ON (TR.PermissionID=TP.ID)
	WHERE RoleID=? ORDER BY TP.ID`)

	rows, err := r.rbac.db.Query(query, roleId)
	if err != nil {
		return nil, err
	}

	var permissions Permissions
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

func (r roleManager) UnassignPermissions(role Role) error {
	var err error
	var roleId int64

	roleId, err = r.rbac.Roles().getRoleId(role)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("DELETE FROM rolepermissions WHERE RoleID=?")
	_, err = r.rbac.db.Exec(query, roleId)

	if err != nil {
		return err
	}

	return nil
}

func (r roleManager) UnassignUsers(role Role) error {
	var err error
	var roleId int64

	roleId, err = r.rbac.Roles().getRoleId(role)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("DELETE FROM userroles WHERE RoleID=?")
	_, err = r.rbac.db.Exec(query, roleId)

	if err != nil {
		return err
	}

	return nil
}

func (r roleManager) getRoleId(role Role) (int64, error) {
	var roleId int64
	var err error
	if _, ok := role.(int64); ok {
		roleId = role.(int64)
	} else if _, ok := role.(string); ok {
		if role.(string)[:1] == "/ " {
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

func (r roleManager) pathId(path string) (int64, error) {
	return r.entity.pathId(path)
}

func (r roleManager) deleteConditional(id int64) error {
	return r.entity.deleteConditional(id)
}

func (r roleManager) deleteSubtreeConditional(id int64) error {
	return r.entity.deleteSubtreeConditional(id)
}

func (r roleManager) pathConditional(id int64) (map[int64]string, error) {
	return r.entity.pathConditional(id)
}

func (r roleManager) Count() (int64, error) {
	return r.entity.Count()
}
func (r roleManager) GetDescription(id int64) (string, error) {
	return r.entity.GetTitle(id)
}

func (r roleManager) GetTitle(id int64) (string, error) {
	return r.entity.GetTitle(id)
}

func (r roleManager) GetPath(id int64) (string, error) {
	return r.entity.GetPath(id)
}

func (r roleManager) Depth(id int64) (int64, error) {
	return r.entity.Depth(id)
}
