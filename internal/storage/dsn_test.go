package storage_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"perimeter/ent"
	"perimeter/internal/storage"
)

func TestSQLiteDSN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", storage.SQLiteDSN(path))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}

	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.SQLite, db)))
	defer client.Close()
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatalf("Schema.Create: %v", err)
	}

	ctx := context.Background()
	const writers, iterations, readers = 8, 25, 4
	errCh := make(chan error, writers+readers)

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range iterations {
				if err := writeTarget(ctx, client, fmt.Sprintf("w%d-i%d.example.com", id, i)); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	for r := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				if _, err := client.Target.Query().All(ctx); err != nil {
					errCh <- fmt.Errorf("reader %d: %w", r, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent access: %v", err)
	}
}

func writeTarget(ctx context.Context, client *ent.Client, input string) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	if _, err := tx.Target.Create().SetInput(input).Save(ctx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
