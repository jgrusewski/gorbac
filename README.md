# gorbac

RBAC Authorization library for Go. 
It provides developers with NIST Level 2 Standard Role Based Access Control and more.

Ported from http://phprbac.net

**Why RBAC?**
Role Based Access Control is the standard means of authorization (access control). The other approach is ACLs, where a table defines who can do what. ACLs are only good for very small systems, because of the following reasons:

Big systems have lots of permits
- People move in organizations, and all their permits should be changed when they do
- Maintenance (adding, changing, removing) of 100,000 permits requires a handful of staff
- Maintenance of the permits assigned to each user, requires more staff than above!
- One wrong user-permit and you have a serious breach in your security, so no room for error

RBAC separates the concepts of Users, Roles and Permissions. Roles are defined in a system, then Permissions defined separately. Then the security administrator decides what role should be permitted to do what action, by assigning that role to the permission. Finally users are assigned to roles. The system does the rest.

- Still lots of permits in the system are the problem
- People move, and only their roles need to be changed
- Maintenance of permits is still an issue
- Maintenance of permits assigned to each role is easy, it doesn't change much logically.
- Role-Permission assignments can be double checked so that no wrong permit is given to any role

That was NIST Level 1 standard RBAC above, and it still had issues. NIST Level 2 RBAC requires Roles and/or Permissions to be hierarchical, so that management of them can easily be handled in hierarchies. The figure below demonstrates a system in hierarchical RBAC:

![alt tag](http://phprbac.net/img/rbac.png)
(source: http://phprbac.net)
