package storage

// SQLiteDSN builds the modernc.org/sqlite DSN for a file-backed database.
// WAL keeps readers from blocking writers; _txlock=immediate makes ent's
// DEFERRED transactions take the write lock at BEGIN so contention is
// serialized by busy_timeout instead of failing with SQLITE_BUSY under
// concurrent workers (issue #45).
func SQLiteDSN(path string) string {
	return "file:" + path +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"
}
