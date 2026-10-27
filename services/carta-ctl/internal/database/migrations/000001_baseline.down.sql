-- The baseline migration only adopts the schema that predates the migration
-- system (it was created by EnsureTables). Rolling it back would destroy user
-- data, so there is nothing to undo.
SELECT 1;
