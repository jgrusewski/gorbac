package rbac

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
)

type Entity interface {
	Add(title string, description string, parentId int64) (int64, error)
	AddPath(path string, descriptions []string) (int, error)

	Assign(role Role, permission Permission) (int64, error)
	//Children()
	//Count()
	//Depth()
	//Descendants()
	//Edit()
	//GetDescription()
	//GetPath()
	//GetTitle()
	//ParentNode()
	pathId(path string) (int64, error)
	//ReturnId()
	titleId(title string) (int64, error)
	//Unassign()
	reset(ensure bool) error
	resetAssignments(ensure bool) error
	deleteConditional(id int64) error
	deleteSubtreeConditional(id int64) error
}

type entityHolder interface {
	getTable() string
}

const (
	Left  string = "lft"
	Right        = "rght"
)

var ErrTitleNotFound = errors.New("title not found")
var ErrPathNotFound = errors.New("path not found")

type entity struct {
	rbac         *rbac
	entityHolder entityHolder
}

func (e entity) Assign(role Role, permission Permission) (int64, error) {
	return e.rbac.Assign(role, permission)
}

func (e entity) Add(title, description string, parentId int64) (int64, error) {
	e.lock()
	defer e.unlock()

	if parentId == 0 {
		parentId = int64(e.rbac.rootId())
	}

	var query string
	var left, right int

	query = fmt.Sprintf("SELECT `%s` AS `right`, `%s` AS `left` FROM %s WHERE id=?", Right, Left, e.entityHolder.getTable())

	err := e.rbac.db.QueryRow(query, parentId).Scan(&right, &left)
	if err != nil {
		return -1, err
	}

	query = fmt.Sprintf("UPDATE %s SET %s = %s + 2 WHERE %s >= ?", e.entityHolder.getTable(), Right, Right, Right)
	_, err = e.rbac.db.Exec(query, right)
	if err != nil {
		return -1, err
	}

	query = fmt.Sprintf("UPDATE %s SET %s = %s + 2 WHERE %s > ?", e.entityHolder.getTable(), Left, Left, Left)
	_, err = e.rbac.db.Exec(query, right)
	if err != nil {
		return -1, err
	}

	query = fmt.Sprintf("INSERT INTO %s (`%s`, `%s`, `title`, `description`) VALUES (?,?,?,?)", e.entityHolder.getTable(), Right, Left)

	res, err := e.rbac.db.Exec(query, right+1, right, title, description)
	if err != nil {
		return -1, err
	}
	insertId, _ := res.LastInsertId()

	return insertId, nil
}

func (e entity) titleId(title string) (int64, error) {
	var id int64

	query := fmt.Sprintf("SELECT id FROM %s WHERE title=?", e.entityHolder.getTable())
	err := e.rbac.db.QueryRow(query, title).Scan(&id)
	if err != nil {
		if err != sql.ErrNoRows {
			return -1, err
		} else {
			return -1, ErrTitleNotFound
		}
	}
	return id, nil
}

func (e entity) lock() {
	e.rbac.db.Exec("LOCK TABLE " + e.entityHolder.getTable() + " WRITE")
}

func (e entity) unlock() {
	e.rbac.db.Exec("UNLOCK TABLES")
}

func (e entity) reset(ensure bool) error {
	var err error

	if !ensure {
		log.Fatal("You must pass true to this function, otherwise it won't work.")
	}

	_, err = e.rbac.db.Exec(fmt.Sprintf("DELETE FROM %s", e.entityHolder.getTable()))
	if err != nil {
		return err
	}

	_, err = e.rbac.db.Exec(fmt.Sprintf("ALTER TABLE %s AUTO_INCREMENT=1;", e.entityHolder.getTable()))
	if err != nil {
		return err
	}

	_, err = e.rbac.db.Exec(fmt.Sprintf("INSERT INTO %s (Title, Description, Lft, Rght) Values(?,?,?,?)", e.entityHolder.getTable()), "root", "root", 0, 1)
	if err != nil {
		return err
	}

	return nil
}

func (e entity) resetAssignments(ensure bool) error {
	var err error
	if !ensure {
		log.Fatal("You must pass true to this function, otherwise it won't work.")
	}

	_, err = e.rbac.db.Exec("DELETE FROM rolepermissions")
	if err != nil {
		return err
	}

	_, err = e.rbac.db.Exec("ALTER TABLE rolepermissions AUTO_INCREMENT =1")
	if err != nil {
		return err
	}

	e.Assign(e.rbac.rootId(), e.rbac.rootId())

	return nil
}

func (e entity) pathId(path string) (int64, error) {
	var parts []string
	path = "root" + path

	if path[len(path)-1:] == "/" {
		path = path[:len(path)-1]
	}

	parts = strings.Split(path, "/")

	gc := "GROUP_CONCAT(parent.Title ORDER BY parent.Lft SEPARATOR '/')"

	var query = fmt.Sprintf(`
		SELECT 
			node.ID, %s AS path 
		FROM 
			%s AS node,
			%s AS parent
		WHERE 
			node.%s BETWEEN parent.%s And parent.%s
		AND  node.Title=?
		GROUP BY node.ID
		HAVING path = ?`, gc, e.entityHolder.getTable(), e.entityHolder.getTable(), Left, Left, Right)

	var id int64

	err := e.rbac.db.QueryRow(query, parts[len(parts)-1], path).Scan(&id)
	if err != nil {
		if err != sql.ErrNoRows {
			return -1, err
		} else {
			return -1, ErrPathNotFound
		}
	}

	return id, nil
}

func (e entity) AddPath(path string, descriptions []string) (int, error) {
	if path[:1] != "/" {
		return 0, fmt.Errorf("The path supplied is not valid.")
	}

	var parts []string
	var err error

	var nodesCreated int
	var currentPath string
	var pathId int64
	var parentId int64

	path = path[1:]
	parts = strings.Split(path, "/")

	var description string
	for i, part := range parts {
		if len(descriptions) > i {
			description = descriptions[i]
			_ = description
		}

		currentPath += "/" + part

		pathId, err = e.pathId(currentPath)
		if err != ErrPathNotFound {
			return nodesCreated, err
		}

		if pathId == 0 {
			parentId, err = e.Add(part, description, parentId)
			if err != nil {
				return nodesCreated, err
			}

			nodesCreated++
		} else {
			parentId = pathId
		}
	}

	return nodesCreated, nil
}

func (e entity) deleteConditional(id int64) error {
	var left, right int64
	query := fmt.Sprintf(`SELECT %s, %s
		FROM %s 
	WHERE ID=? LIMIT 1`, Left, Right, e.entityHolder.getTable())

	err := e.rbac.db.QueryRow(query, id).Scan(&left, &right)
	if err != nil {
		return err
	}

	_, err = e.rbac.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE %s = ?", e.entityHolder.getTable(), Left), left)
	if err != nil {
		return err
	}

	query = fmt.Sprintf("UPDATE %s SET %s = %s -1, %s = %s -1 WHERE %s BETWEEN ? AND ?", e.entityHolder.getTable(), Right, Right, Left, Left, Left)
	_, err = e.rbac.db.Query(query, left, right)
	if err != nil {
		return err
	}

	query = fmt.Sprintf("UPDATE %s SET %s = %s -2 WHERE %s > ?", e.entityHolder.getTable(), Right, Right, Right)
	_, err = e.rbac.db.Exec(query, right)
	if err != nil {
		fmt.Println(err)
		return err
	}

	query = fmt.Sprintf("UPDATE %s SET %s = %s -2 WHERE %s > ?", e.entityHolder.getTable(), Left, Left, Left)
	_, err = e.rbac.db.Query(query, right)
	if err != nil {
		return err
	}

	return nil
}

func (e entity) deleteSubtreeConditional(id int64) error {
	var left, right, width int64
	query := fmt.Sprintf(`SELECT %s, %s, %s-%s+1 as Width
		FROM %s 
	WHERE ID=? LIMIT 1`, Left, Right, Right, Left, e.entityHolder.getTable())

	err := e.rbac.db.QueryRow(query, id).Scan(&left, &right, &width)
	if err != nil {
		return err
	}

	query = fmt.Sprintf("DELETE FROM %s WHERE %s BETWEEN ? AND ?", e.entityHolder.getTable(), Left)
	_, err = e.rbac.db.Query(query, right)
	if err != nil {
		return err
	}

	query = fmt.Sprintf("UPDATE %s SET %s = %s - ? WHERE %s > ?", e.entityHolder.getTable(), Right, Right, Right)
	_, err = e.rbac.db.Query(query, width, right)
	if err != nil {
		return err
	}

	query = fmt.Sprintf("UPDATE %s SET %s = %s - ? WHERE %s > ?", e.entityHolder.getTable(), Left, Left, Left)
	_, err = e.rbac.db.Query(query, width, right)
	if err != nil {
		return err
	}

	return nil
}
