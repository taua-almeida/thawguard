package auth

// Grants is the repository-aware authorization model: the global role set
// filtered to Admin plus every repository-scoped role a user holds. It is
// pure and has no HTTP callers yet; session hydration and handler wiring
// stay on the global RoleSet until cutover. Its state is unexported so a
// Grants value can only be built through NewGrants and only answers
// authorization questions through its capability methods.
type Grants struct {
	// global carries at most the Admin role. Legacy global freezer, thaw
	// approver, and viewer rows in user_roles authorize nothing here.
	global RoleSet
	// byRepository maps a repository ID to the roles granted on it.
	byRepository map[int64]RoleSet
}

// RepositoryRoles returns the roles a repository grant may carry, in the
// same relative order Roles() uses so scoped and global sets render alike.
// Admin is deliberately absent: admin remains a global concern.
func RepositoryRoles() []Role {
	return []Role{RoleFreezer, RoleThawApprover, RoleViewer}
}

func (r Role) ValidForRepository() bool {
	switch r {
	case RoleFreezer, RoleThawApprover, RoleViewer:
		return true
	default:
		return false
	}
}

// NewGrants normalizes a user's global role set and scoped grants into a
// Grants value: global roles other than Admin are dropped, scoped roles
// that are not repository roles are dropped, and repository IDs that cannot
// identify a repository are dropped.
func NewGrants(global RoleSet, scoped map[int64]RoleSet) Grants {
	grants := Grants{global: RoleSet{}, byRepository: map[int64]RoleSet{}}
	if global.Contains(RoleAdmin) {
		grants.global = RoleSet{RoleAdmin}
	}
	for repositoryID, roles := range scoped {
		if repositoryID <= 0 {
			continue
		}
		kept := make(RoleSet, 0, len(roles))
		for _, role := range RepositoryRoles() {
			if roles.Contains(role) {
				kept = append(kept, role)
			}
		}
		if len(kept) > 0 {
			grants.byRepository[repositoryID] = kept
		}
	}
	return grants
}

// CanViewRepository reports whether the user may view the repository: Admin
// views every repository, and any scoped role views its own. An invalid
// repository ID denies access even for Admin.
func (g Grants) CanViewRepository(repositoryID int64) bool {
	if repositoryID <= 0 {
		return false
	}
	if g.global.Contains(RoleAdmin) {
		return true
	}
	return len(g.byRepository[repositoryID]) > 0
}

// CanFreezeRepository reports whether the user may freeze the repository.
// Only a scoped Freezer grant qualifies; Admin never implies it.
func (g Grants) CanFreezeRepository(repositoryID int64) bool {
	if repositoryID <= 0 {
		return false
	}
	return g.byRepository[repositoryID].Contains(RoleFreezer)
}

// CanThawRepository reports whether the user may approve thaws for the
// repository. Only a scoped Thaw approver grant qualifies; Admin never
// implies it.
func (g Grants) CanThawRepository(repositoryID int64) bool {
	if repositoryID <= 0 {
		return false
	}
	return g.byRepository[repositoryID].Contains(RoleThawApprover)
}
