package gorbac

type Permissions struct {
	rbac   *Rbac
	entity entityInternal
	table  string
}

// Permission can be ID, Title or Path
type Permission interface{}

type permission struct {
	ID          int64
	Title       string
	Description string
}

func newPermissions(r *Rbac) *Permissions {
	var permissions = new(Permissions)
	permissions.table = "permissions"
	permissions.rbac = r
	permissions.entity = &entity{rbac: r, entityHolder: permissions}
	return permissions
}

func (p Permissions) Assign(role RoleInterface, permission Permission) (int64, error) {
	return p.entity.assign(role, permission)
}

func (p Permissions) Unassign(role RoleInterface, permission Permission) error {
	return p.entity.unassign(role, permission)
}

func (p Permissions) Add(title string, description string, parentID int64) (int64, error) {
	return p.entity.add(title, description, parentID)
}

func (p Permissions) TitleID(title string) (int64, error) {
	return p.entity.titleID(title)
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

func (p Permissions) GetPermissionID(permission Permission) (int64, error) {
	var permissionID int64
	var err error
	if _, ok := permission.(int64); ok {
		permissionID = permission.(int64)
	} else if _, ok := permission.(string); ok {
		if permission.(string)[:1] == "/ " {
			permissionID, err = p.entity.pathID(permission.(string))
			if err != nil {
				return 0, err
			}
		} else {
			permissionID, err = p.entity.titleID(permission.(string))
			if err != nil {
				return 0, err
			}
		}
	}

	return permissionID, nil
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

func (p Permissions) ReturnID(entity string) (int64, error) {
	return p.entity.pathID(entity)
}

func (p Permissions) Descendants(absolute bool, id int64) ([]path, error) {
	return p.entity.descendants(absolute, id)
}

func (p Permissions) Children(id int64) ([]path, error) {
	return p.entity.children(id)
}
