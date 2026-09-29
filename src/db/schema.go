package db

import (
	"context"

	"github.com/uptrace/bun"
)

// createSchema installs tables and upgrades existing scanner databases.
func createSchema(ctx context.Context, handle *bun.DB) error {
	for _, model := range []any{(*Match)(nil), (*Scan)(nil), (*JARMSighting)(nil), (*Ack)(nil),
		(*JARMBlacklistEntry)(nil), (*ScanPass)(nil), (*ManualScan)(nil)} {
		if _, err := handle.NewCreateTable().Model(model).IfNotExists().Exec(ctx); err != nil {
			return err
		}
	}
	// IfNotExists leaves a table an older build created untouched, so columns added later have
	// to be added by hand. The only error expected here is "duplicate column name". That is the
	// normal case on every run after the first.
	for _, col := range []string{
		"scans ADD COLUMN not_before BIGINT",
		"scans ADD COLUMN serial_number VARCHAR",
		"scans ADD COLUMN self_signed BOOLEAN",
		"scans ADD COLUMN jarm VARCHAR",
		"scans ADD COLUMN manual BOOLEAN NOT NULL DEFAULT FALSE",
		"scans ADD COLUMN full_scanned_at BIGINT NOT NULL DEFAULT 0",
		"matches ADD COLUMN first_seen VARCHAR",
		"matches ADD COLUMN confidence_level INTEGER",
		"scan_passes ADD COLUMN timing_version INTEGER NOT NULL DEFAULT 0",
		"scan_passes ADD COLUMN tls_samples_us VARCHAR NOT NULL DEFAULT ''",
		"scan_passes ADD COLUMN jarm_samples_us VARCHAR NOT NULL DEFAULT ''",
		"scan_passes ADD COLUMN tls_failures BIGINT NOT NULL DEFAULT 0",
		"scan_passes ADD COLUMN jarm_failures BIGINT NOT NULL DEFAULT 0",
		"scan_passes ADD COLUMN dial_samples_us VARCHAR NOT NULL DEFAULT ''",
		"scan_passes ADD COLUMN complete_samples_us VARCHAR NOT NULL DEFAULT ''",
	} {
		handle.ExecContext(ctx, "ALTER TABLE "+col) //nolint:errcheck
	}
	var hasIsOpen int
	if err := handle.NewRaw("SELECT COUNT(*) FROM pragma_table_info('scans') WHERE name = 'is_open'").
		Scan(ctx, &hasIsOpen); err != nil {
		return err
	}
	if hasIsOpen == 0 {
		tx, err := handle.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "ALTER TABLE scans ADD COLUMN is_open BOOLEAN NOT NULL DEFAULT TRUE"); err == nil {
			_, err = tx.ExecContext(ctx, "UPDATE scans SET is_open = TRUE")
		}
		if err == nil {
			err = tx.Commit()
		} else {
			tx.Rollback() //nolint:errcheck
		}
		if err != nil {
			return err
		}
	}
	// Before full_scanned_at existed, every non-manual result came from the scheduled or CLI
	// full sweep. Preserve those known full-scan observations during the migration.
	handle.ExecContext(ctx, "UPDATE scans SET full_scanned_at = scanned_at WHERE full_scanned_at = 0 AND manual = FALSE") //nolint:errcheck
	return nil
}
