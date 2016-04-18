package rbac

type PermissionManager interface {
	Entity

	getPermissionId(permission Permission) (int64, error)
}

type permissionManager struct {
	rbac   *rbac
	entity entityInternal
	table  string
}

type Permission interface{}
type Permissions []permission

type permission struct {
	Id          int64
	Title       string
	Description string
}

func NewPermissionManager(r *rbac) PermissionManager {
	var permissionManager = new(permissionManager)
	permissionManager.table = "permissions"
	permissionManager.rbac = r
	permissionManager.entity = &entity{rbac: r, entityHolder: permissionManager}
	return permissionManager
}

func (p permissionManager) Assign(role Role, permission Permission) (int64, error) {
	return p.entity.assign(role, permission)
}

func (p permissionManager) Add(title string, description string, parentId int64) (int64, error) {
	return p.entity.add(title, description, parentId)
}

func (p permissionManager) TitleId(title string) (int64, error) {
	return p.entity.titleId(title)
}

func (p permissionManager) getTable() string {
	return p.table
}

func (p permissionManager) ResetAssignments(ensure bool) error {
	return p.entity.resetAssignments(ensure)
}

func (p permissionManager) Reset(ensure bool) error {
	return p.entity.reset(ensure)
}

func (p permissionManager) AddPath(path string, description []string) (int, error) {
	return p.entity.addPath(path, description)
}

func (p permissionManager) getPermissionId(permission Permission) (int64, error) {
	var permissionId int64
	var err error
	if _, ok := permission.(int64); ok {
		permissionId = permission.(int64)
	} else if _, ok := permission.(string); ok {
		if permission.(string)[:1] == "/ " {
			permissionId, err = p.entity.pathId(permission.(string))
			if err != nil {
				return 0, err
			}
		} else {
			permissionId, err = p.entity.titleId(permission.(string))
			if err != nil {
				return 0, err
			}
		}
	}

	return permissionId, nil
}

func (p permissionManager) Count() (int64, error) {
	return p.entity.count()
}

func (p permissionManager) GetDescription(id int64) (string, error) {
	return p.entity.getDescription(id)
}

func (p permissionManager) GetTitle(id int64) (string, error) {
	return p.entity.getTitle(id)
}

func (p permissionManager) GetPath(id int64) (string, error) {
	return p.entity.getPath(id)
}

func (p permissionManager) Depth(id int64) (int64, error) {
	return p.entity.depth(id)
}

func (p permissionManager) Edit(id int64) error {
	return nil
}
