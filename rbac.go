package gorbac

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	// Import go-sql-driver package
	_ "github.com/go-sql-driver/mysql"
)

// Config MySQL connection string
type Config struct {
	Name     string
	Host     string
	Port     int
	Username string
	Password string
}

type Rbac struct {
	permissions *Permissions
	roles       *Roles
	users       Owners // Default

	extensions map[string]Owners

	db *sql.DB
}

// New returns a new instance of Rbac
func New(config *Config) *Rbac {
	var rbac = new(Rbac)

	rbac.roles = newRoleManager(rbac)
	rbac.permissions = newPermissions(rbac)
	rbac.users = newUsers(rbac)

	rbac.extensions = make(map[string]Owners, 1)
	rbac.AddOwnerExtension("users", newUsers(rbac))

	if config.Port == 0 {
		config.Port = 3306
	}

	var err error
	rbac.db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true", config.Username, config.Password, config.Host, config.Port, config.Name))
	if err != nil {
		log.Fatal(err)
	}

	return rbac
}

func (r *Rbac) AddOwnerExtension(name string, extension Owners) error {
	if r.extensions[name] != nil {
		return fmt.Errorf("extestion with: (%v) already loaded", name)
	}

	r.extensions[name] = extension

	return nil
}

func (r *Rbac) OwnerExtension(name string) Owners {
	return r.extensions[name]
}

func (r *Rbac) DB() *sql.DB {
	return r.db
}

// Assign a role to a permission.
// Returns true if successful, false if unsuccessful.
func (r Rbac) Assign(role RoleInterface, permission Permission) (int64, error) {
	var err error
	var roleID int64
	var permissionID int64

	roleID, err = r.Roles().GetRoleID(role)
	if err != nil {
		return 0, err
	}

	permissionID, err = r.permissions.GetPermissionID(permission)
	if err != nil {
		return 0, err
	}

	res, err := r.db.Exec("INSERT INTO role_permissions (role_id, permission_id, assignment_date) VALUES(?,?,?)", roleID, permissionID, time.Now().Nanosecond())
	if err != nil {
		return 0, err
	}

	insertID, _ := res.LastInsertId()

	return insertID, nil
}

// Unassign a Role-Permission relation.
func (r Rbac) Unassign(role RoleInterface, permission Permission) error {
	var err error
	var roleID int64
	var permissionID int64

	roleID, err = r.Roles().GetRoleID(role)
	if err != nil {
		return err
	}

	permissionID, err = r.permissions.GetPermissionID(permission)
	if err != nil {
		return err
	}

	_, err = r.db.Exec("DELETE FROM role_permissions WHERE role_id=? AND permission_id=?", roleID, permissionID)

	if err != nil {
		return err
	}

	return nil
}

// Check whether a user has a permission or not.
// Returns true if a user has a permission, false if otherwise.
func (r Rbac) Check(permission Permission, userID UserInterface) (bool, error) {
	if _, ok := userID.(string); ok {
		if userID.(string) == "" {
			return false, ErrUserRequired
		}
	} else if _, ok := userID.(int64); ok {
		if userID.(int64) == 0 {
			return false, ErrUserRequired
		}
	}

	permissionID, err := r.permissions.GetPermissionID(permission)
	if err != nil {
		return false, err
	}

	if permissionID == 0 {
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
	err = r.db.QueryRow(query, userID, permissionID).Scan(&result)
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

// Reset all roles, permissions and assignments.
// Ensure is a required boolean parameter. If true is not passed an fatal will be thrown.
func (r Rbac) Reset(ensure bool) {
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

// Permissions exposes underlaying permissions struct
func (r Rbac) Permissions() *Permissions {
	return r.permissions
}

// Roles exposes underlaying roles struct
func (r Rbac) Roles() *Roles {
	return r.roles
}

// Users exposes underlaying users struct
func (r Rbac) Users() Owners {
	return r.users
}

func (r Rbac) rootID() int64 {
	return 1
}
