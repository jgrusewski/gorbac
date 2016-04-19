package gorbac

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// User can be Id(int,string)
type User interface{}

type UserManager interface {
	Assign(role Role, userId User) (int64, error)
	Unassign(role Role, userId User) error
	AllRoles(userId User) ([]role, error)
	HasRole(role Role, userId User) (bool, error)
	RoleCount(userId User) (int64, error)
	ResetAssignments(ensure bool) error
}

type userManager struct {
	rbac  *rbac
	table string
}

var ErrUserRequired = errors.New("user_id is a required argument")

func newUserManager(r *rbac) UserManager {
	var userManager = new(userManager)
	userManager.table = "user_roles"
	userManager.rbac = r
	return userManager
}

// Assigns a role to a user
func (u userManager) Assign(role Role, userId User) (int64, error) {
	var err error
	var roleId int64

	if _, ok := userId.(string); ok {
		if userId.(string) == "" {
			return 0, ErrUserRequired
		}
	} else if _, ok := userId.(int64); ok {
		if userId.(int64) == 0 {
			return 0, ErrUserRequired
		}
	}

	if _, ok := role.(int64); ok {
		roleId = role.(int64)
	} else if _, ok := role.(string); ok {
		if role.(string)[:1] == "/" {
			roleId, err = u.rbac.Roles().GetRoleId(role.(string))
			if err != nil {
				return 0, err
			}
		} else {
			roleId, err = u.rbac.Roles().TitleId(role.(string))
			if err != nil {
				return 0, err
			}
		}
	}

	if roleId > 0 {
		var query = fmt.Sprintf("INSERT INTO %s (user_id, role_id, assignment_date) VALUES(?,?,?)", u.getTable())
		res, err := u.rbac.db.Exec(query, userId, roleId, time.Now().Nanosecond())
		if err != nil {
			return 0, err
		}

		insertId, _ := res.LastInsertId()

		return insertId, nil
	}

	return 0, fmt.Errorf("role could not be found")
}

// Checks to see whether a User has a Role or not.
func (u userManager) HasRole(role Role, userId User) (bool, error) {
	if _, ok := userId.(string); ok {
		if userId.(string) == "" {
			return false, ErrUserRequired
		}
	} else if _, ok := userId.(int64); ok {
		if userId.(int64) == 0 {
			return false, ErrUserRequired
		}
	}

	roleId, err := u.rbac.Roles().GetRoleId(role)
	if err != nil {
		return false, err
	}

	query := fmt.Sprintf(`
	SELECT COUNT(*) FROM user_roles AS TUR
	JOIN roles AS TRdirect ON (TRdirect.ID=TUR.role_id)
	JOIN roles AS TR ON (TR.Lft BETWEEN TRdirect.Lft AND TRdirect.Rght)
	WHERE
	TUR.user_id=? AND TR.ID=?`)

	var result int64
	err = u.rbac.db.QueryRow(query, userId, roleId).Scan(&result)
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

// Unassigns a Role from a User.
func (u userManager) Unassign(role Role, userId User) error {
	if _, ok := userId.(string); ok {
		if userId.(string) == "" {
			return ErrUserRequired
		}
	} else if _, ok := userId.(int64); ok {
		if userId.(int64) == 0 {
			return ErrUserRequired
		}
	}

	roleId, err := u.rbac.roles.GetRoleId(role)
	if err != nil {
		return err
	}

	_, err = u.rbac.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE user_id=? AND role_id=?", u.getTable()), userId, roleId)
	if err != nil {
		return err
	}

	return nil
}

// Returns all Roles of a User.
func (u userManager) AllRoles(userId User) ([]role, error) {
	if _, ok := userId.(string); ok {
		if userId.(string) == "" {
			return nil, ErrUserRequired
		}
	} else if _, ok := userId.(int64); ok {
		if userId.(int64) == 0 {
			return nil, ErrUserRequired
		}
	}

	query := fmt.Sprintf(`
		SELECT
			TR.Id, TR.Title, TR.Description
		FROM
			%s AS TRel
		JOIN roles AS TR ON
		(TRel.role_id=TR.ID)
		WHERE TRel.user_id=?`, u.getTable())

	rows, err := u.rbac.db.Query(query, userId)
	if err != nil {
		return nil, err
	}

	var roles []role
	for rows.Next() {
		var role role
		err := rows.Scan(&role.Id, &role.Title, &role.Description)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (u userManager) RoleCount(userId User) (int64, error) {
	if _, ok := userId.(string); ok {
		if userId.(string) == "" {
			return 0, ErrUserRequired
		}
	} else if _, ok := userId.(int64); ok {
		if userId.(int64) == 0 {
			return 0, ErrUserRequired
		}
	}

	var result int64
	err := u.rbac.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) AS Result FROM %s WHERE user_id=?", u.getTable()), userId).Scan(&result)

	if err != nil {
		return 0, err
	}

	return result, err
}

func (u userManager) getTable() string {
	return u.table
}

func (u userManager) ResetAssignments(ensure bool) error {
	if !ensure {
		log.Fatal("You must pass true to this function, otherwise it won't work.")
	}

	var err error
	_, err = u.rbac.db.Exec("DELETE FROM user_roles")
	if err != nil {
		return err
	}
	_, err = u.rbac.db.Exec("ALTER TABLE user_roles AUTO_INCREMENT =1")
	if err != nil {
		return err
	}

	u.Assign("root", u.rbac.rootId())

	return nil
}
