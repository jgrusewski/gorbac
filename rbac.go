package rbac

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Rbac interface {
	Assign(Role, Permission) (int64, error)
	Check(permission Permission, userId int64) (bool, error)
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

	roleId, err = r.Roles().getRoleId(role)
	if err != nil {
		return 0, err
	}

	permissionId, err = r.permissions.getPermissionId(permission)
	if err != nil {
		return 0, err
	}

	res, err := r.db.Exec("INSERT INTO rolepermissions (RoleID, PermissionID, AssignmentDate) VALUES(?,?,?)", roleId, permissionId, time.Now().Nanosecond())
	if err != nil {
		return 0, err
	}

	insertId, _ := res.LastInsertId()

	return insertId, nil
}

func (r rbac) Check(permission Permission, userId int64) (bool, error) {
	if userId == 0 {
		return false, fmt.Errorf("userId cannot be null")
	}

	permissionId, err := r.permissions.getPermissionId(permission)
	if err != nil {
		return false, err
	}

	if permissionId == 0 {
		return false, fmt.Errorf("permission not found")
	}

	lastPart := `
	ON ( TR.ID = TRel.RoleID)
 							WHERE
 							TUrel.UserID=?
 							AND
 							TPdirect.ID=?
	`
	query := fmt.Sprintf(`SELECT COUNT(*) AS Result
	FROM
		userroles AS TUrel
	JOIN roles AS TRdirect ON (TRdirect.ID=TUrel.RoleID)
	JOIN roles AS TR ON ( TR.Lft BETWEEN TRdirect.Lft AND TRdirect.Rght)
	JOIN
		(permissions AS TPdirect
			JOIN permissions AS TP ON (TPdirect.Lft BETWEEN TP.Lft AND TP.Rght)
			JOIN rolepermissions AS TRel ON (TP.ID=TRel.PermissionID)
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
	if err := r.roles.resetAssignments(ensure); err != nil {
		log.Fatal(err)
	}
	if err := r.roles.reset(ensure); err != nil {
		log.Fatal(err)
	}

	if err := r.permissions.reset(ensure); err != nil {
		log.Fatal(err)
	}

	if err := r.users.resetAssignments(ensure); err != nil {
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
