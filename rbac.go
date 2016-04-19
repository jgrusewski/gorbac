package rbac

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Rbac interface {
	// Assign a role to a permission (or vice-verse)
	// Returns insert id on success.
	Assign(Role, Permission) (int64, error)

	// Unassign a role to a permission (or vice-verse)
	Unassign(Role, Permission) error

	// Check whether a user has a permission or not.
	// Returns true if a user has a permission, false if otherwise.
	Check(permission Permission, userId int64) (bool, error)

	// Remove all roles, permissions and assignments.
	// (ensure) Is a required boolean parameter. If true is not passed an fatal will be raised.
	Reset(ensure bool)

	Permissions() PermissionManager
	Roles() RoleManager
	Users() UserManager
}

type Config struct {
	Name     string
	Host     string
	Port     int
	Username string
	Password string
}

type rbac struct {
	permissions PermissionManager
	roles       RoleManager
	users       UserManager

	db *sql.DB
}

// Initialize a new Rbac Role Manager
func New(config *Config) Rbac {
	var rbac = new(rbac)

	rbac.roles = NewRoleManager(rbac)
	rbac.permissions = NewPermissionManager(rbac)
	rbac.users = NewUserManager(rbac)

	var err error
	rbac.db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true", config.Username, config.Password, config.Host, config.Port, config.Name))
	if err != nil {
		log.Fatal(err)
	}

	return rbac
}

func (r *rbac) Assign(role Role, permission Permission) (int64, error) {
	var err error
	var roleId int64
	var permissionId int64

	roleId, err = r.Roles().GetRoleId(role)
	if err != nil {
		return 0, err
	}

	permissionId, err = r.permissions.GetPermissionId(permission)
	if err != nil {
		return 0, err
	}

	res, err := r.db.Exec("INSERT INTO role_permissions (role_id, permission_id, AssignmentDate) VALUES(?,?,?)", roleId, permissionId, time.Now().Nanosecond())
	if err != nil {
		return 0, err
	}

	insertId, _ := res.LastInsertId()

	return insertId, nil
}

func (r *rbac) Unassign(role Role, permission Permission) error {
	var err error
	var roleId int64
	var permissionId int64

	roleId, err = r.Roles().GetRoleId(role)
	if err != nil {
		return err
	}

	permissionId, err = r.permissions.GetPermissionId(permission)
	if err != nil {
		return err
	}

	_, err = r.db.Exec("DELETE FROM role_permissions WHERE RoleId=? AND permission_id=?", roleId, permissionId)

	if err != nil {
		return err
	}

	return nil
}

func (r rbac) Check(permission Permission, userId int64) (bool, error) {
	if userId == 0 {
		return false, fmt.Errorf("userId cannot be null")
	}

	permissionId, err := r.permissions.GetPermissionId(permission)
	if err != nil {
		return false, err
	}

	if permissionId == 0 {
		return false, fmt.Errorf("permission not found")
	}

	lastPart := `
	ON ( TR.ID = TRel.role_id)
 							WHERE
 							TUrel.user_id=?
 							AND
 							TPdirect.ID=?
	`
	query := fmt.Sprintf(`SELECT COUNT(*) AS Result
	FROM
		user_roles AS TUrel
	JOIN roles AS TRdirect ON (TRdirect.ID=TUrel.role_id)
	JOIN roles AS TR ON ( TR.Lft BETWEEN TRdirect.Lft AND TRdirect.Rght)
	JOIN
		(permissions AS TPdirect
			JOIN permissions AS TP ON (TPdirect.Lft BETWEEN TP.Lft AND TP.Rght)
			JOIN role_permissions AS TRel ON (TP.ID=TRel.permission_id)
		) %s`, lastPart)

	var result int64
	err = r.db.QueryRow(query, userId, permissionId).Scan(&result)
	if err != nil {
		if err != sql.ErrNoRows {
			return false, err
		}
	}

	if result > 0 {
		return true, nil
	}

	return false, nil
}

func (r rbac) Reset(ensure bool) {
	if err := r.roles.ResetAssignments(ensure); err != nil {
		log.Fatal(err)
	}
	if err := r.roles.Reset(ensure); err != nil {
		log.Fatal(err)
	}

	if err := r.permissions.Reset(ensure); err != nil {
		log.Fatal(err)
	}

	if err := r.users.ResetAssignments(ensure); err != nil {
		log.Fatal(err)
	}
}

func (r *rbac) rootId() int64 {
	return 1
}

func (r rbac) Permissions() PermissionManager {
	return r.permissions
}

func (r rbac) Roles() RoleManager {
	return r.roles
}

func (r rbac) Users() UserManager {
	return r.users
}
