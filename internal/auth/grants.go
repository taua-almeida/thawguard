package auth

import "github.com/taua-almeida/thawguard/internal/repositoryscope"

// Grants is the live authorization model: explicit installation Admin state
// plus every repository-scoped role a user holds. Its state is unexported so a
// Grants value can only be built through NewGrants and only answers
// authorization questions through its capability methods.
type Grants struct {
	isAdmin bool
	// byRepository maps a repository ID to the roles granted on it.
	byRepository map[int64]RoleSet
}

// RepositoryRoles returns the roles a repository grant may carry, in the
// canonical order used by repository access views and mutations. Admin is
// deliberately absent: Admin remains an installation concern.
func RepositoryRoles() []Role {
	return []Role{RoleViewer, RoleFreezer, RoleThawApprover}
}

func (r Role) ValidForRepository() bool {
	switch r {
	case RoleFreezer, RoleThawApprover, RoleViewer:
		return true
	default:
		return false
	}
}

// NewGrants copies and normalizes explicit Admin state and scoped grants into
// a Grants value. Scoped roles that are not repository roles and repository
// IDs that cannot identify a repository are dropped.
func NewGrants(isAdmin bool, scoped map[int64]RoleSet) Grants {
	grants := Grants{isAdmin: isAdmin, byRepository: map[int64]RoleSet{}}
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

// CanManageInstallation reports whether the user is an installation Admin.
// It grants installation/repository configuration and Users & Access
// management, but never repository-scoped freeze or thaw actions.
func (g Grants) CanManageInstallation() bool {
	return g.isAdmin
}

// HasRepositoryAccess reports whether the user can read at least one
// repository. Admin read-all authority qualifies even when no scoped grants
// exist; a zero-access user does not.
func (g Grants) HasRepositoryAccess() bool {
	return g.CanManageInstallation() || len(g.byRepository) > 0
}

// CanViewRepository reports whether the user may view the repository: Admin
// views every repository, and any scoped role views its own. An invalid
// repository ID denies access even for Admin.
func (g Grants) CanViewRepository(repositoryID int64) bool {
	if repositoryID <= 0 {
		return false
	}
	if g.isAdmin {
		return true
	}
	return len(g.byRepository[repositoryID]) > 0
}

// RepositoryReadScope projects the grants onto repository read queries:
// Admin reads every repository, any scoped role reads its own repository,
// and no grants — including the zero value — reads none. The scope reflects
// only this Grants snapshot, so it stays as fresh as the SessionByID request
// that produced it; callers must not rebuild it from storage.
func (g Grants) RepositoryReadScope() repositoryscope.ReadScope {
	if g.isAdmin {
		return repositoryscope.All()
	}
	ids := make([]int64, 0, len(g.byRepository))
	for repositoryID := range g.byRepository {
		ids = append(ids, repositoryID)
	}
	return repositoryscope.IDs(ids...)
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
