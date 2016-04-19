package gorbac

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
)

type Entity interface {
	Add(title string, description string, parentId int64) (int64, error)
	AddPath(path string, descriptions []string) (int64, error)

	Assign(role Role, permission Permission) (int64, error)
	Count() (int64, error)
	Depth(id int64) (int64, error)
	Descendants(absolute bool, id int64) ([]path, error)
	Edit(id int64, title, description string) error
	TitleId(title string) (int64, error)

	Unassign(role Role, permission Permission) error
	Children(id int64) ([]path, error)

	ReturnId(entity string) (int64, error)
	ParentNode(id int64) (int64, error)
	Reset(ensure bool) error
	ResetAssignments(ensure bool) error

	GetDescription(Id int64) (string, error)
	GetTitle(id int64) (string, error)

	GetPath(id int64) (string, error)
}

type entityInternal interface {
	add(title string, description string, parentId int64) (int64, error)
	addPath(path string, descriptions []string) (int64, error)

	assign(role Role, permission Permission) (int64, error)
	count() (int64, error)
	depth(id int64) (int64, error)
	descendants(absolute bool, id int64) ([]path, error)

	edit(id int64, title, description string) error
	unassign(role Role, permission Permission) error
	returnId(entity string) (int64, error)
	children(id int64) ([]path, error)
	getDescription(id int64) (string, error)
	getTitle(id int64) (string, error)

	getPath(id int64) (string, error)
	reset(ensure bool) error
	resetAssignments(ensure bool) error

	pathId(path string) (int64, error)
	titleId(title string) (int64, error)
	deleteConditional(id int64) error
	deleteSubtreeConditional(id int64) error
	pathConditional(id int64) ([]path, error)
	parentNode(id int64) (int64, error)
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

type path struct {
	Id          int64
	Title       string
	Description string
	Depth       int64
}

func (e entity) assign(role Role, permission Permission) (int64, error) {
	return e.rbac.Assign(role, permission)
}

func (e entity) unassign(role Role, permission Permission) error {
	return e.rbac.Unassign(role, permission)
}

func (e entity) add(title, description string, parentId int64) (int64, error) {
	e.lock()

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
	e.rbac.db.Query("LOCK TABLE " + e.entityHolder.getTable())
}

func (e entity) unlock() {
	e.rbac.db.Query("UNLOCK TABLES")
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

	_, err = e.rbac.db.Exec("DELETE FROM role_permissions")
	if err != nil {
		return err
	}

	_, err = e.rbac.db.Exec("ALTER TABLE role_permissions AUTO_INCREMENT =1")
	if err != nil {
		return err
	}

	e.assign(e.rbac.rootId(), e.rbac.rootId())

	return nil
}

func (e entity) pathId(path string) (int64, error) {
	var parts []string
	path = "root" + path

	if path[len(path)-1:] == "/" {
		path = path[:len(path)-1]
	}

	parts = strings.Split(path, "/")

	var query = fmt.Sprintf(`
		SELECT 
			node.ID, GROUP_CONCAT(parent.Title ORDER BY parent.Lft ASC SEPARATOR '/') AS path 
		FROM 
			%s AS node,
			%s AS parent
		WHERE 
			node.%s BETWEEN parent.%s And parent.%s
		AND  node.Title=?
		GROUP BY node.ID
		HAVING path = ?`, e.entityHolder.getTable(), e.entityHolder.getTable(), Left, Left, Right)

	var id int64

	var x []uint8
	err := e.rbac.db.QueryRow(query, parts[len(parts)-1], path).Scan(&id, &x)
	if err != nil {
		if err != sql.ErrNoRows {
			return 0, err
		} else {
			return 0, ErrPathNotFound
		}
	}

	return id, nil
}

func (e entity) addPath(path string, descriptions []string) (int64, error) {
	if path[:1] != "/" {
		return 0, fmt.Errorf("The path supplied is not valid.")
	}

	var parts []string
	var err error

	var nodesCreated int64
	var currentPath string
	var pathId int64
	var parentId int64

	path = path[1:]
	parts = strings.Split(path, "/")

	var description string
	for i, part := range parts {
		if len(descriptions) > i {
			description = descriptions[i]
		}
		currentPath += "/" + part

		pathId, err = e.pathId(currentPath)
		if err != ErrPathNotFound {
			return nodesCreated, err
		}

		if pathId == 0 {
			parentId, err = e.add(part, description, parentId)
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

func (e entity) count() (int64, error) {
	var result int64
	err := e.rbac.db.QueryRow("SELECT COUNT(*) FROM %s", e.entityHolder.getTable()).Scan(&result)
	return result, err
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

func (e entity) getDescription(id int64) (string, error) {
	var result string
	err := e.rbac.db.QueryRow(fmt.Sprintf("SELECT description FROM %s WHERE id=?", e.entityHolder.getTable()), id).Scan(&result)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (e entity) getTitle(id int64) (string, error) {
	var result string
	err := e.rbac.db.QueryRow(fmt.Sprintf("SELECT title FROM %s WHERE id=?", e.entityHolder.getTable()), id).Scan(&result)
	if err != nil {
		return "", err
	}

	return result, nil
}

func (e entity) getPath(id int64) (string, error) {
	res, err := e.pathConditional(id)
	if err != nil {
		return "", err
	}
	if len(res) == 1 {
		return "/", nil
	}

	var output string

	for i, r := range res {
		if i == 0 {
			continue
		}
		output += "/" + r.Title
	}

	return output, nil
}

func (e entity) pathConditional(id int64) ([]path, error) {
	query := fmt.Sprintf(`
		SELECT parent.ID, parent.Title
		FROM %s AS node,
			%s AS parent
		WHERE node.%s BETWEEN parent.%s AND parent.%s
		AND ( node.id=? )
		ORDER BY parent.%s`, e.entityHolder.getTable(), e.entityHolder.getTable(), Left, Left, Right, Left)

	rows, err := e.rbac.db.Query(query, id)
	if err != nil {
		return nil, err
	}

	var result []path
	for rows.Next() {
		var id int64
		var title string
		err := rows.Scan(&id, &title)
		if err != nil {
			return nil, err
		}
		result = append(result, path{Id: id, Title: title})
	}

	return result, nil
}

func (e entity) depth(id int64) (int64, error) {
	res, err := e.pathConditional(id)
	if err != nil {
		return 0, err
	}

	return int64(len(res) - 1), nil
}

func (e entity) edit(id int64, title, description string) error {
	query := fmt.Sprintf("UPDATE %s SET title=?, description=? WHERE id=?", e.entityHolder.getTable())
	_, err := e.rbac.db.Exec(query, title, description, id)
	if err != nil {
		return err
	}

	return nil
}

func (e entity) parentNode(id int64) (int64, error) {
	res, err := e.pathConditional(id)
	if err != nil {
		return 0, err
	}

	if len(res) < 2 {
		return 0, nil
	}

	return res[len(res)-2].Id, nil
}

func (e entity) returnId(entity string) (int64, error) {
	var entityId int64
	var err error
	if entity[:1] == "/" {
		entityId, err = e.pathId(entity)
	} else {
		entityId, err = e.titleId(entity)
	}

	return entityId, err
}

func (e entity) descendants(absolute bool, id int64) ([]path, error) {
	var depthConcat string
	if !absolute {
		depthConcat = "- (sub_tree.innerDepth )"
	}
	query := fmt.Sprintf(`
            SELECT node.ID, node.Title, node.Description, (COUNT(parent.ID)-1 %s) AS Depth
            FROM %s AS node,
            	%s AS parent,
            	%s AS sub_parent,
            	(
            		SELECT node.ID, (COUNT(parent.ID) - 1) AS innerDepth
            		FROM %s AS node,
            		%s AS parent
            		WHERE node.%s BETWEEN parent.%s AND parent.%s
            		AND (node.ID=?)
            		GROUP BY node.ID
            		ORDER BY node.%s
            	) AS sub_tree
            WHERE node.%s BETWEEN parent.%s AND parent.%s
            	AND node.%s BETWEEN sub_parent.%s AND sub_parent.%s
            	AND sub_parent.ID = sub_tree.ID
            GROUP BY node.ID
            HAVING Depth > 0
            ORDER BY node.%s
	`, depthConcat, e.entityHolder.getTable(), e.entityHolder.getTable(), e.entityHolder.getTable(), e.entityHolder.getTable(), e.entityHolder.getTable(), Left, Left, Right, Left, Left, Left, Right, Left, Left, Right, Left)

	var result []path
	rows, err := e.rbac.db.Query(query, id)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var p path
		err := rows.Scan(&p.Id, &p.Title, &p.Description, &p.Depth)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}

	return result, nil
}

func (e entity) children(id int64) ([]path, error) {
	query := fmt.Sprintf(`
            SELECT node.ID, node.Title, node.Description,(COUNT(parent.ID)-1 - (sub_tree.innerDepth )) AS Depth
            FROM %s AS node,
            	%s AS parent,
            	%s AS sub_parent,
            	(
            		SELECT node.ID, (COUNT(parent.ID) - 1) AS innerDepth
            		FROM %s AS node,
            		%s AS parent
            		WHERE node.%s BETWEEN parent.%s AND parent.%s
            		AND (node.ID=?)
            		GROUP BY node.ID
            		ORDER BY node.%s
            	) AS sub_tree
            WHERE node.%s BETWEEN parent.%s AND parent.%s
            	AND node.%s BETWEEN sub_parent.%s AND sub_parent.%s
            	AND sub_parent.ID = sub_tree.ID
            GROUP BY node.ID
            HAVING Depth > 0
            ORDER BY node.%s
	`, e.entityHolder.getTable(), e.entityHolder.getTable(), e.entityHolder.getTable(), e.entityHolder.getTable(), e.entityHolder.getTable(), Left, Left, Right, Left, Left, Left, Right, Left, Left, Right, Left)

	var result []path
	rows, err := e.rbac.db.Query(query, id)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var p path
		err := rows.Scan(&p.Id, &p.Title, &p.Description, &p.Depth)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}

	return result, nil

}
