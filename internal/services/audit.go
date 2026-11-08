package services

import (
	"database/sql"
	"fmt"
	"regexp"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

type AuditService struct {
	db *sql.DB
}

func NewAuditService(db *sql.DB) *AuditService {
	return &AuditService{db: db}
}

func (s *AuditService) Log(action, details string) {
	s.db.Exec("INSERT INTO audit_log (action, details) VALUES (?, ?)", action, details)
}

// vinRe matches a VIN (17 characters, no I, O or Q). Details never carry one
// now, and v30 scrubbed old rows; this is the last line of defence.
var vinRe = regexp.MustCompile(`\b[A-HJ-NPR-Z0-9]{17}\b`)

// Recent returns the newest entries first, with any VIN replaced.
func (s *AuditService) Recent(limit int) ([]models.AuditLog, error) {
	rows, err := s.db.Query(
		"SELECT id, action, details, timestamp FROM audit_log ORDER BY id DESC LIMIT ?", limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var entry models.AuditLog
		if err := rows.Scan(&entry.ID, &entry.Action, &entry.Details, &entry.Timestamp); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		entry.Details = vinRe.ReplaceAllString(entry.Details, "[VIN]")
		logs = append(logs, entry)
	}
	return logs, rows.Err()
}

// Summary is how many entries the log holds and when the oldest was written.
func (s *AuditService) Summary() (total int, since string, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*), COALESCE(MIN(timestamp), '') FROM audit_log`).Scan(&total, &since)
	return total, since, err
}
