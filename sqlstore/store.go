// Package sqlstore provides a relational store for the guard interfaces built
// on the standard database/sql package. It implements guard.CredentialStore
// (bcrypt password hashes) and guard.RoleStore over a normalized schema:
//
//	users      (email PRIMARY KEY, password_hash)
//	user_roles (email REFERENCES users, role, PRIMARY KEY (email, role))
//
// The package is an optional, separately versioned module: it pulls in no SQL
// driver itself, so any driver (postgres, mysql, mariadb, sqlite, ...) works.
// The schema uses portable SQL; the SET-OR-INSERT upsert in SetUser follows the
// same rule, so no driver-specific syntax is required.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/hydopt/guard"
	"golang.org/x/crypto/bcrypt"
)

// dummyHash is compared against when a user row is missing, so an unknown email
// costs the same bcrypt work as a known one, blunting timing-based account
// enumeration.
var dummyHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("guard:missing-user"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return h
}()

// Store is a guard.CredentialStore and guard.RoleStore backed by two SQL
// tables: a users table holding bcrypt password hashes and a user_roles join
// table holding role assignments.
type Store struct {
	db         *sql.DB
	usersTable string
	rolesTable string
}

// NewStore returns a Store backed by db, storing users in usersTable and their
// roles in rolesTable. Call Migrate to create the tables.
func NewStore(db *sql.DB, usersTable, rolesTable string) *Store {
	return &Store{db: db, usersTable: usersTable, rolesTable: rolesTable}
}

// Migrate creates the users and user_roles tables if they do not exist.
func (s *Store) Migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS ` + s.usersTable + ` (
			email         TEXT PRIMARY KEY,
			password_hash BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + s.rolesTable + ` (
			email TEXT NOT NULL REFERENCES ` + s.usersTable + `(email) ON DELETE CASCADE,
			role  TEXT NOT NULL,
			PRIMARY KEY (email, role)
		)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}
	return nil
}

// SetUser upserts a user with the given roles, replacing any previous role
// assignments. The password is bcrypt-hashed and never stored in plaintext.
func (s *Store) SetUser(ctx context.Context, email, password string, roles ...string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("sqlstore: hash password: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlstore: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := upsertUser(ctx, tx, s.usersTable, email, hash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.rolesTable+" WHERE email = ?", email); err != nil {
		return fmt.Errorf("sqlstore: clear roles: %w", err)
	}
	for _, role := range roles {
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.rolesTable+" (email, role) VALUES (?, ?)", email, role); err != nil {
			return fmt.Errorf("sqlstore: insert role: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlstore: commit: %w", err)
	}
	return nil
}

// upsertUser is a driver-portable upsert: UPDATE first, INSERT on the race
// between the two is acceptable for provisioning, and the transaction rolls
// back on error.
func upsertUser(ctx context.Context, tx *sql.Tx, table, email string, hash []byte) error {
	res, err := tx.ExecContext(ctx, "UPDATE "+table+" SET password_hash = ? WHERE email = ?", hash, email)
	if err != nil {
		return fmt.Errorf("sqlstore: update user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: rows affected: %w", err)
	}
	if n == 0 {
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+table+" (email, password_hash) VALUES (?, ?)", email, hash); err != nil {
			return fmt.Errorf("sqlstore: insert user: %w", err)
		}
	}
	return nil
}

// Authenticate implements guard.CredentialStore. It loads the email's bcrypt
// hash and compares the password. Unknown emails run a dummy comparison before
// returning guard.ErrUnauthorized, so callers cannot tell an unknown user from
// a wrong password.
func (s *Store) Authenticate(ctx context.Context, email, password string) error {
	var hash []byte
	err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM "+s.usersTable+" WHERE email = ?", email).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) || len(hash) == 0 {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return guard.ErrUnauthorized
	}
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return guard.ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return guard.ErrUnauthorized
	}
	return nil
}

// RolesByEmail implements guard.RoleStore. A user without role rows has no
// roles. Storage errors are returned rather than swallowed as "no roles".
func (s *Store) RolesByEmail(ctx context.Context, email string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT role FROM "+s.rolesTable+" WHERE email = ? ORDER BY role", email)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: roles: %w", err)
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("sqlstore: roles: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: roles: %w", err)
	}
	return roles, nil
}
