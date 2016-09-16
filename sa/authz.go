package sa

import (
	"fmt"
	"strings"
	"time"

	gorp "gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/core"
)

var authorizationTables = []string{
	"authz",
	"pendingAuthorizations",
}

var pendingStatuses = []core.AcmeStatus{
	core.StatusPending,
	core.StatusProcessing,
	core.StatusUnknown,
}

const getAuthorizationIDsMax = 1000

func statusIsPending(status core.AcmeStatus) bool {
	for _, pendingStatus := range pendingStatuses {
		if status == pendingStatus {
			return true
		}
	}
	return false
}

func countPending(tx *gorp.Transaction, id string) int64 {
	var count int64

	// New pending authz's go into the `authz` db table[0] so that the legacy
	// `pendingAuthorizations` table can be dropped when there are no longer any
	// unexpired pending auth rows in it. Until that point both the authz table
	// and the pendingAuthorizations need to be consulted to determine if
	// a pending authz exists.
	//
	// [0] - https://github.com/letsencrypt/boulder/issues/2162
	for _, table := range authorizationTables {
		stmtArgs := []interface{}{id}
		qmarks := []string{}
		for _, status := range pendingStatuses {
			stmtArgs = append(stmtArgs, string(status))
			qmarks = append(qmarks, "?")
		}
		statusStmt := fmt.Sprintf("(%s)", strings.Join(qmarks, ", "))
		var tableCount int64
		_ = tx.SelectOne(&tableCount, fmt.Sprintf(`
SELECT count(*)
FROM %s
WHERE id = ?
AND status IN %s`, table, statusStmt),
			stmtArgs...)
		count += tableCount
	}

	return count
}

func existingPending(tx *gorp.Transaction, id string) bool {
	return countPending(tx, id) > 0
}

func existingFinal(tx *gorp.Transaction, id string) bool {
	var count int64
	stmtArgs := []interface{}{id}
	qmarks := []string{}
	for _, status := range pendingStatuses {
		stmtArgs = append(stmtArgs, string(status))
		qmarks = append(qmarks, "?")
	}
	statusStmt := fmt.Sprintf("(%s)", strings.Join(qmarks, ", "))
	_ = tx.SelectOne(&count, fmt.Sprintf(`
SELECT count(*)
FROM authz
WHERE id = ?
AND status NOT IN %s`, statusStmt),
		stmtArgs...)
	return count > 0
}

func getAuthorizationIDsByDomain(db *gorp.DbMap, tableName string, ident string, now time.Time) ([]string, error) {
	var allIDs []string
	_, err := db.Select(
		&allIDs,
		fmt.Sprintf(
			`SELECT id FROM %s
       WHERE identifier = :ident AND
       status != :invalid AND
       status != :revoked AND
       expires > :now
       LIMIT :limit`,
			tableName,
		),
		map[string]interface{}{
			"ident":   ident,
			"invalid": string(core.StatusInvalid),
			"revoked": string(core.StatusRevoked),
			"now":     now,
			"limit":   getAuthorizationIDsMax,
		},
	)
	if err != nil {
		return nil, err
	}
	return allIDs, nil
}

func revokeAuthorizations(db *gorp.DbMap, tableName string, authIDs []string) (int64, error) {
	stmtArgs := []interface{}{string(core.StatusRevoked)}
	qmarks := []string{}
	for _, id := range authIDs {
		stmtArgs = append(stmtArgs, id)
		qmarks = append(qmarks, "?")
	}
	idStmt := fmt.Sprintf("(%s)", strings.Join(qmarks, ", "))
	result, err := db.Exec(
		fmt.Sprintf(
			`UPDATE %s
       SET status = ?
       WHERE id IN %s`,
			tableName,
			idStmt,
		),
		stmtArgs...,
	)
	if err != nil {
		return 0, err
	}
	batchSize, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return batchSize, nil
}
