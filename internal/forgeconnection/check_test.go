package forgeconnection

import (
	"errors"
	"testing"

	"github.com/taua-almeida/thawguard/internal/audit"
)

func TestCheckBindsIdentitiesAndReplacesPreview(t *testing.T) {
	fixture := newServiceFixture(t)
	first := successObservation()
	second := successObservation()
	second.Organization.Slug = "renamed-org"
	second.Organization.DisplayName = "Renamed Organization"
	second.Repositories = []ObservedRepository{
		{RemoteID: "101", Owner: "renamed-org", Name: "beta", DefaultBranch: "trunk", Private: true},
		{RemoteID: "200", Owner: "renamed-org", Name: "gamma", DefaultBranch: "main", Private: true},
	}
	fixture.observer.observations = []Observation{first, second}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connectionID := fixture.connectionID(t)

	check, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if check.ResultCode != CheckVisibleInventoryObserved ||
		check.ConfigRevision != 1 || check.CheckGeneration != 1 ||
		check.ObservedVersion != "15.0.6" ||
		check.VisibleRepositoryCount == nil || *check.VisibleRepositoryCount != 2 ||
		check.VisiblePrivateRepositoryCount == nil || *check.VisiblePrivateRepositoryCount != 1 {
		t.Fatalf("unexpected check: %+v", check)
	}
	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !connection.Bound() ||
		connection.ServiceUserRemoteID != "42" ||
		connection.Organization.RemoteID != "7" ||
		connection.Organization.Slug != "fixture-org" {
		t.Fatalf("binding missing: %+v", connection)
	}
	preview, err := fixture.service.VisibleRepositories(fixture.ctx, connection.ID)
	if err != nil || len(preview) != 2 {
		t.Fatalf("preview rows = %d err=%v", len(preview), err)
	}

	// The observer received an unbound input first.
	if fixture.observer.inputs[0].BoundServiceUserRemoteID != "" || fixture.observer.inputs[0].BoundOrganizationRemoteID != "" {
		t.Fatalf("first observation input was bound: %+v", fixture.observer.inputs[0])
	}

	// A second successful check refreshes the renamed organization, replaces
	// the preview, and removes the repository that disappeared.
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 1); err != nil {
		t.Fatal(err)
	}
	if fixture.observer.inputs[1].BoundServiceUserRemoteID != "42" || fixture.observer.inputs[1].BoundOrganizationRemoteID != "7" {
		t.Fatalf("second observation input was not bound: %+v", fixture.observer.inputs[1])
	}
	connection, _, err = fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if connection.Organization.RemoteID != "7" ||
		connection.Organization.Slug != "renamed-org" ||
		connection.Organization.DisplayName != "Renamed Organization" {
		t.Fatalf("rename refresh missing: %+v", connection.Organization)
	}
	preview, err = fixture.service.VisibleRepositories(fixture.ctx, connection.ID)
	if err != nil || len(preview) != 2 {
		t.Fatalf("replaced preview rows = %d err=%v", len(preview), err)
	}
	for _, repository := range preview {
		if repository.RemoteID == "100" {
			t.Fatal("disappeared repository was retained in the preview")
		}
		if repository.ObservedCheckGeneration != 2 {
			t.Fatalf("preview generation = %d, want 2", repository.ObservedCheckGeneration)
		}
	}
}

func TestFailedCheckRetainsLastSuccessfulPreview(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.observer.observations = []Observation{
		successObservation(),
		{ResultCode: CheckUnavailable, ObservedVersion: "15.0.6"},
	}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connectionID := fixture.connectionID(t)
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 1); err != nil {
		t.Fatal(err)
	}
	check, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if check.ResultCode != CheckUnavailable || check.CheckGeneration != 2 ||
		check.VisibleRepositoryCount != nil || check.VisiblePrivateRepositoryCount != nil {
		t.Fatalf("unexpected failure evidence: %+v", check)
	}
	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := fixture.service.VisibleRepositories(fixture.ctx, connection.ID)
	if err != nil || len(preview) != 2 {
		t.Fatalf("failure dropped the retained preview: rows=%d err=%v", len(preview), err)
	}
	for _, repository := range preview {
		if repository.ObservedCheckGeneration != 1 {
			t.Fatalf("retained preview generation = %d, want 1", repository.ObservedCheckGeneration)
		}
	}
}

func TestCheckRevisionFenceAndUnprovenPrivateRead(t *testing.T) {
	fixture := newServiceFixture(t)
	unproven := successObservation()
	unproven.ResultCode = CheckVisibleInventoryObservedPrivateReadUnproven
	unproven.Repositories = []ObservedRepository{
		{RemoteID: "100", Owner: "fixture-org", Name: "alpha", DefaultBranch: "main", Private: false},
	}
	fixture.observer.observations = []Observation{unproven}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connectionID := fixture.connectionID(t)
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected revision fence, got %v", err)
	}
	check, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if check.ResultCode != CheckVisibleInventoryObservedPrivateReadUnproven ||
		check.VisiblePrivateRepositoryCount == nil || *check.VisiblePrivateRepositoryCount != 0 {
		t.Fatalf("unexpected unproven check: %+v", check)
	}
}

// TestConcurrentChecksPersistOnlyHighestGeneration proves the generation
// fence in both completion orders: whichever reservation is newest when a
// completion arrives is the only one allowed to persist.
func TestConcurrentChecksPersistOnlyHighestGeneration(t *testing.T) {
	for _, olderFinishesFirst := range []bool{false, true} {
		name := "newer completes first"
		if olderFinishesFirst {
			name = "older completes first"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			older := successObservation()
			newer := successObservation()
			// The newer snapshot keeps only the private repository, so the
			// winning preview is distinguishable from the older one.
			newer.Repositories = successObservation().Repositories[1:]
			fixture.observer.observations = []Observation{older, newer}
			fixture.observer.gates = []chan struct{}{make(chan struct{}), make(chan struct{})}
			fixture.observer.started = make(chan struct{}, 2)
			if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
				t.Fatal(err)
			}
			connectionID := fixture.connectionID(t)

			results := make(chan error, 2)
			run := func() {
				_, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 1)
				results <- err
			}
			go run()
			<-fixture.observer.started // generation 1 reserved and observing
			go run()
			<-fixture.observer.started // generation 2 reserved and observing

			release := []int{1, 0}
			if olderFinishesFirst {
				release = []int{0, 1}
			}
			errorsByCall := make([]error, 2)
			for _, call := range release {
				close(fixture.observer.gates[call])
				errorsByCall[call] = <-results
			}
			// The older reservation must never persist; the newer one must.
			if !errors.Is(errorsByCall[0], ErrCheckStale) {
				t.Fatalf("older check error = %v, want ErrCheckStale", errorsByCall[0])
			}
			if errorsByCall[1] != nil {
				t.Fatalf("newer check error = %v", errorsByCall[1])
			}

			connection, _, err := fixture.service.Current(fixture.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if connection.SetupCheck == nil || connection.SetupCheck.CheckGeneration != 2 {
				t.Fatalf("persisted evidence generation: %+v", connection.SetupCheck)
			}
			preview, err := fixture.service.VisibleRepositories(fixture.ctx, connection.ID)
			if err != nil || len(preview) != 1 {
				t.Fatalf("persisted preview = %d rows err=%v (older check may have won)", len(preview), err)
			}
		})
	}
}

// TestResetRecreateCannotAcceptOldCompletion proves the reset/recreate ABA
// fence: a completion reserved against the deleted connection can never
// persist into an identically configured recreation, even at matching
// revision and generation numbers, because the internal id is never reused.
func TestResetRecreateCannotAcceptOldCompletion(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.observer.observations = []Observation{successObservation(), successObservation()}
	fixture.observer.gates = []chan struct{}{make(chan struct{}), nil}
	fixture.observer.started = make(chan struct{}, 2)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	oldConnectionID := fixture.connectionID(t)

	oldResult := make(chan error, 1)
	go func() {
		_, err := fixture.service.Check(fixture.ctx, fixture.adminID, oldConnectionID, 1)
		oldResult <- err
	}()
	<-fixture.observer.started // old check reserved generation 1 and is observing

	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{ExpectedConnectionID: oldConnectionID, ExpectedRevision: 1, ConfirmReset: true}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	// The recreated connection reaches the same revision and generation
	// numbers the old completion was reserved under.
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, fixture.connectionID(t), 1); err != nil {
		t.Fatal(err)
	}
	<-fixture.observer.started

	close(fixture.observer.gates[0])
	if err := <-oldResult; !errors.Is(err, ErrCheckStale) {
		t.Fatalf("old completion error = %v, want ErrCheckStale", err)
	}

	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if connection.SetupCheck == nil || connection.SetupCheck.CheckGeneration != 1 || connection.SetupCheck.ConfigRevision != 1 {
		t.Fatalf("recreated evidence: %+v", connection.SetupCheck)
	}
	// Every preview row belongs to the recreated connection only.
	var foreignRows int
	if err := fixture.database.QueryRow(
		`SELECT count(*) FROM forge_visible_repositories WHERE connection_id != ?`, connection.ID,
	).Scan(&foreignRows); err != nil {
		t.Fatal(err)
	}
	if foreignRows != 0 {
		t.Fatalf("old completion leaked %d preview rows", foreignRows)
	}
}

func TestCheckDecryptFailureIsIncompleteWithoutEvidence(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored ciphertext so decryption fails like a wrong key.
	if _, err := fixture.database.ExecContext(fixture.ctx,
		`UPDATE forgejo_connection_config SET service_pat_ciphertext = x'00'`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, fixture.connectionID(t), 1); !errors.Is(err, ErrCheckIncomplete) {
		t.Fatalf("expected ErrCheckIncomplete, got %v", err)
	}
	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The generation is ahead of evidence: the UI reports an incomplete
	// check, and PAT replacement and reset remain available.
	if connection.CheckGeneration != 1 || connection.SetupCheck != nil {
		t.Fatalf("incomplete check left generation=%d evidence=%+v", connection.CheckGeneration, connection.SetupCheck)
	}
	// The durable reservation carries its own atomic audit record; the
	// interrupted run records no result.
	assertForgeAudit(t, fixture.database, audit.ActionForgeConnectionCheckStarted, connection.ID, map[string]any{
		"revision":   float64(1),
		"generation": float64(1),
	})
	assertForgeAuditCount(t, fixture.database, "forge.connection_checked", 0)
}

func TestCheckRejectsMalformedObservation(t *testing.T) {
	fixture := newServiceFixture(t)
	inconsistent := successObservation()
	// Claims observed private read while listing no private repository.
	inconsistent.Repositories = inconsistent.Repositories[:1]
	fixture.observer.observations = []Observation{inconsistent}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, fixture.connectionID(t), 1); !errors.Is(err, ErrCheckIncomplete) {
		t.Fatalf("expected ErrCheckIncomplete, got %v", err)
	}
	assertForgeAuditCount(t, fixture.database, "forge.connection_check_started", 1)
	assertForgeAuditCount(t, fixture.database, "forge.connection_checked", 0)
}

// TestStaleCommandsCannotTargetRecreatedConnection proves the command-level
// ABA fence: forms carry the never-reused connection id, so an edit, reset,
// or check issued before a reset can never act on an identically configured
// recreation that reached the same revision.
func TestStaleCommandsCannotTargetRecreatedConnection(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.observer.observations = []Observation{successObservation()}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	oldConnectionID := fixture.connectionID(t)
	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{ExpectedConnectionID: oldConnectionID, ExpectedRevision: 1, ConfirmReset: true}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	newConnectionID := fixture.connectionID(t)
	if newConnectionID == oldConnectionID {
		t.Fatalf("connection id %d was reused", newConnectionID)
	}

	staleEdit := validEditInput(oldConnectionID, 1)
	staleEdit.DisplayName = "Stale Edit"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, staleEdit); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit error = %v, want ErrConflict", err)
	}
	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{ExpectedConnectionID: oldConnectionID, ExpectedRevision: 1, ConfirmReset: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale reset error = %v, want ErrConflict", err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, oldConnectionID, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale check error = %v, want ErrConflict", err)
	}
	if len(fixture.observer.inputs) != 0 {
		t.Fatalf("stale check reached the observer: %d observations", len(fixture.observer.inputs))
	}

	// A command without a positive expected id is refused outright.
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, validEditInput(0, 1)); !IsValidationError(err) {
		t.Fatalf("id-less edit error = %v, want validation error", err)
	}

	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found || connection.ID != newConnectionID ||
		connection.Revision != 1 || connection.DisplayName != "Fixture Forge" ||
		connection.CheckGeneration != 0 {
		t.Fatalf("stale commands touched the recreated connection: %+v found=%v err=%v", connection, found, err)
	}
	// Only the genuine reset was audited; the stale attempts recorded nothing.
	assertForgeAuditCount(t, fixture.database, "forge.connection_reset", 1)
	assertForgeAuditCount(t, fixture.database, "forge.connection_updated", 0)
	assertForgeAuditCount(t, fixture.database, "forge.connection_check_started", 0)

	// The recreated connection still accepts commands under its own id.
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, newConnectionID, 1); err != nil {
		t.Fatal(err)
	}
}
