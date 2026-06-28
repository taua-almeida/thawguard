package auth

type Role string

const (
	RoleAdmin        Role = "admin"
	RoleFreezer      Role = "freezer"
	RoleThawApprover Role = "thaw_approver"
	RoleViewer       Role = "viewer"
)

func (r Role) CanManageRepositories() bool { return r == RoleAdmin }
func (r Role) CanFreeze() bool             { return r == RoleAdmin || r == RoleFreezer }
func (r Role) CanThaw() bool               { return r == RoleAdmin || r == RoleThawApprover }
func (r Role) CanView() bool {
	return r == RoleAdmin || r == RoleFreezer || r == RoleThawApprover || r == RoleViewer
}
