package rbac

type RoleManager interface {
	Entity
	HasPermission(roleID, permissionID int) bool

	getRoleId(role Role) (int64, error)
}

type roleManager struct {
	rbac   *rbac
	entity *entity
	table  string
}

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

func (r roleManager) pathId(path string) (int64, error) {
	return r.entity.pathId(path)
}

func (r roleManager) HasPermission(roleID, permissionID int) bool {
	return true
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
				return -1, err
			}
		}
	}

	return roleId, nil
}
