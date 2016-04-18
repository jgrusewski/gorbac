package rbac

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

type UserManager interface {
	//HasPermission(roleID, permissionID int) bool
	Assign(role Role, userId int64) (int64, error)
	Unassign(role Role, userId int64) error
	AllRoles(userId int64) (Roles, error)
	HasRole(role Role, userId int64) (bool, error)
	RoleCount(userId int64) (int64, error)
	ResetAssignments(ensure bool) error
}

type userManager struct {
	rbac *rbac
	//entity *entity
	table string
}

var ErrUserRequired = errors.New("UserID is a required argument")

func NewUserManager(r *rbac) UserManager {
	var userManager = new(userManager)
	userManager.table = "userroles"
	userManager.rbac = r
	return userManager
}

func (u userManager) Assign(role Role, userId int64) (int64, error) {
	var err error
	var roleId int64

	if userId == 0 {
		return 0, fmt.Errorf("userId cannot be null")
	}

	if _, ok := role.(int64); ok {
		roleId = role.(int64)
	} else if _, ok := role.(string); ok {
		if role.(string)[:1] == "/" {
			log.Fatal("todo fix go by path")
		} else {
			roleId, err = u.rbac.Roles().TitleId(role.(string))
			if err != nil {
				return 0, err
			}
		}
	}

	if roleId > 0 {
		var query = fmt.Sprintf("INSERT INTO %s (UserID, RoleID, AssignmentDate) VALUES(?,?,?)", u.getTable())
		res, err := u.rbac.db.Exec(query, userId, roleId, time.Now().Nanosecond())
		if err != nil {
			return 0, err
		}

		insertId, _ := res.LastInsertId()

		return insertId, nil
	}

	return 0, fmt.Errorf("role could not be found")
}

func (u userManager) HasRole(role Role, userId int64) (bool, error) {
	if userId == 0 {
		return false, ErrUserRequired
	}

	roleId, err := u.rbac.Roles().getRoleId(role)
	if err != nil {
		return false, err
	}

	query := fmt.Sprintf(`
	SELECT COUNT(*) FROM userroles AS TUR
	JOIN roles AS TRdirect ON (TRdirect.ID=TUR.RoleID)
	JOIN roles AS TR ON (TR.Lft BETWEEN TRdirect.Lft AND TRdirect.Rght)
	WHERE
	TUR.UserID=? AND TR.ID=?`)

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

func (u userManager) Unassign(role Role, userId int64) error {
	if userId == 0 {
		return ErrUserRequired
	}

	roleId, err := u.rbac.roles.getRoleId(role)
	if err != nil {
		return err
	}

	_, err = u.rbac.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE UserId=? AND RoleId=?", u.getTable()), userId, roleId)
	if err != nil {
		return err
	}

	return nil
}

func (u userManager) AllRoles(userId int64) (Roles, error) {
	if userId == 0 {
		return nil, ErrUserRequired
	}
	query := fmt.Sprintf(`
		SELECT
			TR.Id, TR.Title, TR.Description
		FROM
			%s AS TRel
		JOIN roles AS TR ON
		(TRel.RoleID=TR.ID)
		WHERE TRel.UserID=?`, u.getTable())

	rows, err := u.rbac.db.Query(query, userId)
	if err != nil {
		return nil, err
	}

	var roles Roles
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

func (u userManager) RoleCount(userId int64) (int64, error) {
	var result int64
	err := u.rbac.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) AS Result FROM %s WHERE UserID=?", u.getTable()), userId).Scan(&result)

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
	_, err = u.rbac.db.Exec("DELETE FROM userroles")
	if err != nil {
		return err
	}
	_, err = u.rbac.db.Exec("ALTER TABLE userroles AUTO_INCREMENT =1")
	if err != nil {
		return err
	}

	u.Assign("root", u.rbac.rootId())

	return nil
}
