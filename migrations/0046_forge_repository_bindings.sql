-- Reversible Forge repository identity bindings.
--
-- A binding joins one exact existing local repository to one immutable
-- repository identity observed through the saved Forge connection. It does
-- not copy mutable remote names or change any repository-owned state.

ALTER TABLE forge_connections
ADD COLUMN binding_revision INTEGER NOT NULL DEFAULT 0
  CHECK (typeof(binding_revision) = 'integer' AND binding_revision >= 0);

CREATE TABLE forge_repository_bindings (
  repository_id INTEGER PRIMARY KEY
    REFERENCES repositories(id) ON DELETE RESTRICT
    CHECK (typeof(repository_id) = 'integer' AND repository_id > 0),
  connection_id INTEGER NOT NULL
    REFERENCES forge_connections(id) ON DELETE RESTRICT
    CHECK (typeof(connection_id) = 'integer' AND connection_id > 0),
  organization_id INTEGER NOT NULL
    CHECK (typeof(organization_id) = 'integer' AND organization_id > 0),
  remote_repository_id TEXT NOT NULL
    CHECK (
      typeof(remote_repository_id) = 'text'
      AND length(CAST(remote_repository_id AS BLOB)) BETWEEN 1 AND 128
    ),
  UNIQUE (connection_id, remote_repository_id),
  FOREIGN KEY (organization_id, connection_id)
    REFERENCES forge_organizations(id, connection_id) ON DELETE RESTRICT
);
