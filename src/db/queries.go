package db

import (
	"context"

	"github.com/uptrace/bun"
)

// SaveMatches upserts a batch of feed hits, refreshing tag and seen_at on conflict.
func SaveMatches(ctx context.Context, rows []Match) error {
	if len(rows) == 0 {
		return nil
	}
	defer invalidateHostState()
	writeMu.Lock()
	defer writeMu.Unlock()
	_, err := Handle.NewInsert().Model(&rows).
		On("CONFLICT (ip, source, value) DO UPDATE").
		Set("tag = EXCLUDED.tag").
		Set("first_seen = EXCLUDED.first_seen").
		Set("confidence_level = EXCLUDED.confidence_level").
		Set("seen_at = EXCLUDED.seen_at").
		Exec(ctx)
	return err
}

// SaveAck records or refreshes one acknowledgement. Written straight through rather than queued:
// it is a single row off a dashboard request, not part of the probe fan-out writeLoop exists to
// batch.
func SaveAck(ctx context.Context, row Ack) error {
	return SaveAcks(ctx, []Ack{row})
}

func SaveAcks(ctx context.Context, rows []Ack) error {
	if len(rows) == 0 {
		return nil
	}
	defer invalidateHostState()
	writeMu.Lock()
	defer writeMu.Unlock()
	_, err := Handle.NewInsert().Model(&rows).
		On("CONFLICT (ip) DO UPDATE").
		Set("acked_at = EXCLUDED.acked_at").
		Set("signature = EXCLUDED.signature").
		Exec(ctx)
	return err
}

// DeleteAck un-acknowledges a host. Unconditional: the operator asked for this row to go, whatever
// it currently says.
func DeleteAck(ctx context.Context, ip string) error {
	return DeleteAcks(ctx, []string{ip})
}

func DeleteAcks(ctx context.Context, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	defer invalidateHostState()
	writeMu.Lock()
	defer writeMu.Unlock()
	_, err := Handle.NewDelete().Model((*Ack)(nil)).Where("ip IN (?)", bun.In(ips)).Exec(ctx)
	return err
}

// RetireAcks drops acknowledgements that no longer describe their host. The signature is part of
// the condition rather than just the reason for calling: between the read that found a row stale
// and this delete, the operator may have acknowledged the host afresh from the dashboard. That new
// Row carries a different signature and has to survive.
//
// One statement per row. Retiring fires once, on the pass that first invalidates an ack, so this
// is almost always nothing or a single row.
func RetireAcks(ctx context.Context, rows []Ack) error {
	if len(rows) == 0 {
		return nil
	}
	defer invalidateHostState()
	writeMu.Lock()
	defer writeMu.Unlock()
	for _, row := range rows {
		if _, err := Handle.NewDelete().Model((*Ack)(nil)).
			Where("ip = ? AND signature = ?", row.IP, row.Signature).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// SaveManualScans records the addresses one operator request covered. Upserted by address: the
// stamp is the most recent hand-scan, and only the fact that there was one is read today.
func SaveManualScans(ctx context.Context, rows []ManualScan) error {
	if len(rows) == 0 {
		return nil
	}
	defer invalidateHostState()
	writeMu.Lock()
	defer writeMu.Unlock()
	_, err := Handle.NewInsert().Model(&rows).
		On("CONFLICT (ip) DO UPDATE").
		Set("scanned_at = EXCLUDED.scanned_at").
		Exec(ctx)
	return err
}

// SaveScanPass records one completed pass. Written straight through rather than queued, like
// SaveAck: it is a single row at the end of a sweep, not part of the probe fan-out writeLoop
// exists to batch.
//
// A pass is a fact about the scanner, so its history is retained for analytics.
func SaveScanPass(ctx context.Context, row ScanPass) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	_, err := Handle.NewInsert().Model(&row).On("CONFLICT (started_at, source) DO NOTHING").Exec(ctx)
	return err
}

// SaveScans upserts a sweep's open ports, replacing what the last sweep saw on conflict.
func SaveScans(ctx context.Context, rows []Scan) error {
	if len(rows) == 0 {
		return nil
	}
	defer invalidateHostState()
	for i := range rows {
		rows[i].IsOpen = true
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	return Handle.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.NewInsert().Model(&rows).
			On("CONFLICT (ip, port) DO UPDATE").
			Set(`is_open = TRUE, scanned_at = EXCLUDED.scanned_at, subject = EXCLUDED.subject,
				manual = EXCLUDED.manual,
				full_scanned_at = MAX(full_scanned_at, EXCLUDED.full_scanned_at),
				issuer = EXCLUDED.issuer, dns_names = EXCLUDED.dns_names,
				not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after,
				signature_algorithm = EXCLUDED.signature_algorithm,
				serial_number = EXCLUDED.serial_number, self_signed = EXCLUDED.self_signed,
				fingerprint = EXCLUDED.fingerprint, jarm = EXCLUDED.jarm`).
			Where("EXCLUDED.scanned_at >= scanned_at").Exec(ctx)
		return err
	})
}

func CloseScans(ctx context.Context, rows []Scan) error {
	if len(rows) == 0 {
		return nil
	}
	defer invalidateHostState()
	writeMu.Lock()
	defer writeMu.Unlock()
	for start := 0; start < len(rows); start += maxBatch {
		batch := rows[start:min(start+maxBatch, len(rows))]
		query := Handle.NewUpdate().Model((*Scan)(nil)).Set("is_open = FALSE")
		query = query.WhereGroup(" AND ", func(query *bun.UpdateQuery) *bun.UpdateQuery {
			for _, row := range batch {
				query = query.WhereOr("(ip = ? AND port = ? AND scanned_at <= ?)", row.IP, row.Port, row.ScannedAt)
			}
			return query
		})
		if _, err := query.Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// SaveJARMSightings upserts one writer flush in one statement. Rescans keep the endpoint row and
// only widen its observed interval.
func SaveJARMSightings(ctx context.Context, rows []JARMSighting) error {
	if len(rows) == 0 {
		return nil
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	_, err := Handle.NewInsert().Model(&rows).
		On("CONFLICT (hash, ip, port) DO UPDATE").
		Set("first_seen = MIN(first_seen, EXCLUDED.first_seen)").
		Set("last_seen = MAX(last_seen, EXCLUDED.last_seen)").
		Exec(ctx)
	return err
}

func upsertJARMBlacklist(ctx context.Context, rows []JARMBlacklistEntry) error {
	if len(rows) == 0 {
		return nil
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	_, err := Handle.NewInsert().Model(&rows).
		On("CONFLICT (hash) DO UPDATE").
		Set("label = EXCLUDED.label").
		Exec(ctx)
	return err
}

func removeJARMBlacklist(ctx context.Context, hash string) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	_, err := Handle.NewDelete().Model((*JARMBlacklistEntry)(nil)).Where("hash = ?", hash).Exec(ctx)
	return err
}

// LoadHostData returns the complete stored state used to build host views in deterministic order.
func LoadHostData(ctx context.Context) (HostData, error) {
	var data HostData
	if err := Handle.NewSelect().Model(&data.Scans).Order("ip", "port").Scan(ctx); err != nil {
		return data, err
	}
	if err := Handle.NewSelect().Model(&data.Matches).Order("ip", "source", "value").Scan(ctx); err != nil {
		return data, err
	}
	if err := Handle.NewSelect().Model(&data.Acks).Order("ip").Scan(ctx); err != nil {
		return data, err
	}
	if err := Handle.NewSelect().Model(&data.Manual).Order("ip").Scan(ctx); err != nil {
		return data, err
	}
	return data, nil
}

func LoadOpenScans(ctx context.Context) ([]Scan, error) {
	var rows []Scan
	err := Handle.NewSelect().Model(&rows).Column("ip", "port").Where("is_open = TRUE").Scan(ctx)
	return rows, err
}

func LoadCertificateScans(ctx context.Context) ([]Scan, error) {
	var stored []Scan
	err := Handle.NewSelect().Model(&stored).Column("ip", "port", "scanned_at", "subject", "dns_names").
		Where("subject != '' OR dns_names != ''").Scan(ctx)
	return stored, err
}

// LoadFullScanPasses returns completed full scans at or after cutoff, oldest first.
func LoadFullScanPasses(ctx context.Context, cutoff int64) ([]ScanPass, error) {
	var rows []ScanPass
	err := Handle.NewSelect().Model(&rows).Where("ports = 65535").Where("started_at >= ?", cutoff).
		Order("started_at").Scan(ctx)
	return rows, err
}

// LoadLatestFullScanPasses returns at most limit completed full scans, newest first.
func LoadLatestFullScanPasses(ctx context.Context, limit int) ([]ScanPass, error) {
	var rows []ScanPass
	err := Handle.NewSelect().Model(&rows).Where("ports = 65535").
		OrderExpr("started_at DESC, source DESC").Limit(limit).Scan(ctx)
	return rows, err
}

// LoadFeedMatches returns the upstream feed hits confirmed at or after cutoff. What they add up to
// is the analytics module's question, not this one's.
func LoadFeedMatches(ctx context.Context, cutoff int64) ([]Match, error) {
	var matches []Match
	err := Handle.NewSelect().Model(&matches).Column("ip", "source", "value").
		Where("source != ? AND seen_at >= ?", JARMBlacklistSource, cutoff).Scan(ctx)
	return matches, err
}

// LoadJARMRows lists lifetime hashes. The sort arrives already parsed: the "-key" grammar belongs
// to the dashboard, and spelling it here made storage the third place that knew it.
func LoadJARMRows(ctx context.Context, sort string, descending bool, needle string) ([]JARMRow, error) {
	rows := []JARMRow{}
	query := Handle.NewSelect().Table("jarm_sightings").
		ColumnExpr("hash").
		ColumnExpr("COUNT(DISTINCT ip) AS hosts").
		ColumnExpr("MIN(first_seen) AS first_seen").
		ColumnExpr("MAX(last_seen) AS last_seen").
		Group("hash")
	// Each sort key picks a column and the tiebreakers that keep the listing deterministic.
	column, tiebreakers := "hosts", ", last_seen DESC, hash ASC"
	switch sort {
	case "recent":
		column, tiebreakers = "last_seen", ", hash ASC"
	case "first":
		column, tiebreakers = "first_seen", ", hash ASC"
	case "hash":
		column, tiebreakers = "hash", ""
	}
	sense := " ASC"
	if descending {
		sense = " DESC"
	}
	query.OrderExpr(column + sense + tiebreakers)
	if needle != "" {
		query.Where("instr(hash, ?) > 0", needle)
	}
	err := query.Scan(ctx, &rows)
	return rows, err
}

func JARMBlacklistEntries(ctx context.Context) ([]JARMBlacklistEntry, error) {
	rows := []JARMBlacklistEntry{}
	err := Handle.NewSelect().Model(&rows).OrderExpr("label COLLATE NOCASE, hash").Scan(ctx)
	return rows, err
}
