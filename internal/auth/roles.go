package auth

import "strings"

type Role string

type RoleSet []Role

const (
	RoleAdmin        Role = "admin"
	RoleFreezer      Role = "freezer"
	RoleThawApprover Role = "thaw_approver"
	RoleViewer       Role = "viewer"
)

func (roles RoleSet) Contains(want Role) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}

func (roles RoleSet) CanManageRepositories() bool { return roles.Contains(RoleAdmin) }
func (roles RoleSet) CanFreeze() bool             { return roles.Contains(RoleFreezer) }
func (roles RoleSet) CanThaw() bool               { return roles.Contains(RoleThawApprover) }
func (roles RoleSet) CanView() bool {
	return roles.Contains(RoleAdmin) || roles.Contains(RoleFreezer) || roles.Contains(RoleThawApprover) || roles.Contains(RoleViewer)
}

func (roles RoleSet) Primary() Role {
	for _, role := range Roles() {
		if roles.Contains(role) {
			return role
		}
	}
	return ""
}

func (roles RoleSet) Label() string {
	labels := make([]string, 0, len(roles))
	for _, role := range roles {
		labels = append(labels, role.Label())
	}
	return strings.Join(labels, ", ")
}

func (roles RoleSet) String() string {
	values := make([]string, 0, len(roles))
	for _, role := range roles {
		values = append(values, string(role))
	}
	return strings.Join(values, ",")
}

func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleFreezer, RoleThawApprover, RoleViewer:
		return true
	default:
		return false
	}
}

func (r Role) Label() string {
	switch r {
	case RoleAdmin:
		return "Admin"
	case RoleFreezer:
		return "Freezer"
	case RoleThawApprover:
		return "Thaw approver"
	case RoleViewer:
		return "Viewer"
	default:
		return string(r)
	}
}

func Roles() []Role {
	return []Role{RoleAdmin, RoleFreezer, RoleThawApprover, RoleViewer}
}

func NormalizeRoleSet(raw []Role) (RoleSet, bool) {
	seen := map[Role]bool{}
	valid := true
	for _, role := range raw {
		role = Role(strings.TrimSpace(string(role)))
		if role == "" {
			continue
		}
		if !role.Valid() {
			valid = false
			continue
		}
		seen[role] = true
	}
	roles := make(RoleSet, 0, len(seen))
	for _, role := range Roles() {
		if seen[role] {
			roles = append(roles, role)
		}
	}
	return roles, valid
}
