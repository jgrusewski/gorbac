package gorbac

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// User can be ID(int,string)
type UserInterface interface{}

type Owner interface{}

type Owners interface {
	Assign(role RoleInterface, owner Owner) (int64, error)
	HasRole(role RoleInterface, owner Owner) (bool, error)
	Unassign(role RoleInterface, owner Owner) error
	AllRoles(owner Owner) ([]Role, error)
	RoleCount(owner Owner) (int64, error)
	ResetAssignments(ensure bool) error
}

type Users struct {
	rbac  *Rbac
	table string
}

var ErrUserRequired = errors.New("user id is a required argument")

func newUsers(r *Rbac) Users {
	var users = Users{}
	users.table = "user_roles"
	users.rbac = r
	return users
}

// Assigns a role to a user
func (u Users) Assign(role RoleInterface, userID Owner) (int64, error) {
	var err error
	var roleID int64

	if _, ok := userID.(string); ok {
		if userID.(string) == "" {
			return 0, ErrUserRequired
		}
	} else if _, ok := userID.(int64); ok {
		if userID.(int64) == 0 {
			return 0, ErrUserRequired
		}
	}

	if _, ok := role.(int64); ok {
		roleID = role.(int64)
	} else if _, ok := role.(string); ok {
		if role.(string)[:1] == "/" {
			roleID, err = u.rbac.Roles().GetRoleID(role.(string))
			if err != nil {
				return 0, err
			}
		} else {
			roleID, err = u.rbac.Roles().TitleID(role.(string))
			if err != nil {
				return 0, err
			}
		}
	}

	if roleID > 0 {
		var query = fmt.Sprintf("INSERT INTO %s (user_id, role_id, assignment_date) VALUES(?,?,?)", u.getTable())
		res, err := u.rbac.db.Exec(query, userID, roleID, time.Now().Nanosecond())
		if err != nil {
			return 0, err
		}

		insertID, _ := res.LastInsertId()

		return insertID, nil
	}

	return 0, fmt.Errorf("role could not be found")
}

// Checks to see whether a UserInterface has a Role or not.
func (u Users) HasRole(role RoleInterface, userID Owner) (bool, error) {
	if _, ok := userID.(string); ok {
		if userID.(string) == "" {
			return false, ErrUserRequired
		}
	} else if _, ok := userID.(int64); ok {
		if userID.(int64) == 0 {
			return false, ErrUserRequired
		}
	}

	roleID, err := u.rbac.Roles().GetRoleID(role)
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
	err = u.rbac.db.QueryRow(query, userID, roleID).Scan(&result)
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

// Unassigns a Role from a User interface.
func (u Users) Unassign(role RoleInterface, userID Owner) error {
	if _, ok := userID.(string); ok {
		if userID.(string) == "" {
			return ErrUserRequired
		}
	} else if _, ok := userID.(int64); ok {
		if userID.(int64) == 0 {
			return ErrUserRequired
		}
	}

	roleID, err := u.rbac.roles.GetRoleID(role)
	if err != nil {
		return err
	}

	_, err = u.rbac.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE user_id=? AND role_id=?", u.getTable()), userID, roleID)
	if err != nil {
		return err
	}

	return nil
}

// Returns all Roles of a User.
func (u Users) AllRoles(userID Owner) ([]Role, error) {
	if _, ok := userID.(string); ok {
		if userID.(string) == "" {
			return nil, ErrUserRequired
		}
	} else if _, ok := userID.(int64); ok {
		if userID.(int64) == 0 {
			return nil, ErrUserRequired
		}
	}

	query := fmt.Sprintf(`
		SELECT
			TR.ID, TR.Title, TR.Description
		FROM
			%s AS TRel
		JOIN roles AS TR ON
		(TRel.role_id=TR.ID)
		WHERE TRel.user_id=?`, u.getTable())

	rows, err := u.rbac.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var role Role
		err := rows.Scan(&role.ID, &role.Title, &role.Description)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (u Users) RoleCount(userID Owner) (int64, error) {
	if _, ok := userID.(string); ok {
		if userID.(string) == "" {
			return 0, ErrUserRequired
		}
	} else if _, ok := userID.(int64); ok {
		if userID.(int64) == 0 {
			return 0, ErrUserRequired
		}
	}

	var result int64
	err := u.rbac.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) AS Result FROM %s WHERE user_id=?", u.getTable()), userID).Scan(&result)

	if err != nil {
		return 0, err
	}

	return result, err
}

func (u Users) getTable() string {
	return u.table
}

func (u Users) ResetAssignments(ensure bool) error {
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

	u.Assign("root", u.rbac.rootID())

	return nil
}
