package gorbac

//type PermissionManager interface {
//	Add(title string, description string, parentId int64) (int64, error)
//	AddPath(path string, descriptions []string) (int64, error)
//
//	Assign(role Role, permission Permission) (int64, error)
//	Count() (int64, error)
//	Depth(id int64) (int64, error)
//	Descendants(absolute bool, id int64) ([]path, error)
//	Edit(id int64, title, description string) error
//	TitleId(title string) (int64, error)
//
//	Unassign(role Role, permission Permission) error
//	Children(id int64) ([]path, error)
//
//	ReturnId(entity string) (int64, error)
//	ParentNode(id int64) (int64, error)
//	Reset(ensure bool) error
//	ResetAssignments(ensure bool) error
//
//	GetDescription(Id int64) (string, error)
//	GetTitle(id int64) (string, error)
//
//	GetPath(id int64) (string, error)
//
//	GetPermissionId(permission Permission) (int64, error)
//}

type Permissions struct {
	rbac   *rbac
	entity entityInternal
	table  string
}

// Permission can be Id, Title or Path
type Permission interface{}

type permission struct {
	Id          int64
	Title       string
	Description string
}

func newPermissions(r *rbac) *Permissions {
	var permissions = new(Permissions)
	permissions.table = "permissions"
	permissions.rbac = r
	permissions.entity = &entity{rbac: r, entityHolder: permissions}
	return permissions
}

func (p Permissions) Assign(role Role, permission Permission) (int64, error) {
	return p.entity.assign(role, permission)
}

func (p Permissions) Unassign(role Role, permission Permission) error {
	return p.entity.unassign(role, permission)
}

func (p Permissions) Add(title string, description string, parentId int64) (int64, error) {
	return p.entity.add(title, description, parentId)
}

func (p Permissions) TitleId(title string) (int64, error) {
	return p.entity.titleId(title)
}

func (p Permissions) getTable() string {
	return p.table
}

func (p Permissions) ResetAssignments(ensure bool) error {
	return p.entity.resetAssignments(ensure)
}

func (p Permissions) Reset(ensure bool) error {
	return p.entity.reset(ensure)
}

func (p Permissions) AddPath(path string, description []string) (int64, error) {
	return p.entity.addPath(path, description)
}

func (p Permissions) GetPermissionId(permission Permission) (int64, error) {
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

func (p Permissions) Count() (int64, error) {
	return p.entity.count()
}

func (p Permissions) GetDescription(id int64) (string, error) {
	return p.entity.getDescription(id)
}

func (p Permissions) GetTitle(id int64) (string, error) {
	return p.entity.getTitle(id)
}

func (p Permissions) GetPath(id int64) (string, error) {
	return p.entity.getPath(id)
}

func (p Permissions) Depth(id int64) (int64, error) {
	return p.entity.depth(id)
}

func (p Permissions) Edit(id int64, title, description string) error {
	return p.entity.edit(id, title, description)
}

func (p Permissions) ParentNode(id int64) (int64, error) {
	return p.entity.parentNode(id)
}

func (p Permissions) ReturnId(entity string) (int64, error) {
	return p.entity.pathId(entity)
}

func (p Permissions) Descendants(absolute bool, id int64) ([]path, error) {
	return p.entity.descendants(absolute, id)
}

func (p Permissions) Children(id int64) ([]path, error) {
	return p.entity.children(id)
}
