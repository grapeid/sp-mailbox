package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// What an operator keeps, and for how long.
//
// The guiding rule is that this service should be able to do its job while
// knowing as little as possible, and should keep what it does know for as short
// a time as it can. Two consequences show up in the schema:
//
//   - Envelope bodies are stored exactly as received and are never parsed.
//     They are ciphertext to this process. Nothing here should ever grow a
//     reason to look inside one.
//   - Everything has an expiry. A mailbox that keeps messages forever becomes
//     an archive of everybody's correspondence, which is a liability to the
//     operator and a risk to the people it serves.

type Store struct {
	db *sql.DB
}

// Enrollment is one AID's claim on a mailbox here.
type Enrollment struct {
	AID          string
	PublicKeyB64 string
	OOBI         string
	DepositToken string
	CreatedAt    time.Time
	LastSeenAt   time.Time
}

// Message is one waiting envelope.
type Message struct {
	ID          string
	AID         string
	Envelope    []byte
	SizeBytes   int
	DepositedAt time.Time
	ExpiresAt   time.Time
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	// One writer. SQLite serialises writes anyway, and a pool only turns that
	// into "database is locked" errors under load.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS enrollments (
    aid            TEXT PRIMARY KEY,
    public_key_b64 TEXT NOT NULL,
    oobi           TEXT NOT NULL DEFAULT '',
    deposit_token  TEXT NOT NULL UNIQUE,
    created_at     TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id           TEXT PRIMARY KEY,
    aid          TEXT NOT NULL,
    envelope     BLOB NOT NULL,
    size_bytes   INTEGER NOT NULL,
    deposited_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL
);
-- Collection always asks "what is waiting for this AID, oldest first", and
-- expiry sweeps by time. Those are the only two access patterns.
CREATE INDEX IF NOT EXISTS idx_messages_aid ON messages(aid, deposited_at);
CREATE INDEX IF NOT EXISTS idx_messages_expiry ON messages(expires_at);

-- Rate limiting is per AID and per source address, in coarse minute buckets.
-- Deliberately not a log: the bucket key carries no timestamp beyond the
-- minute, and old rows are swept, so this cannot be reconstructed into a
-- history of who deposited when.
CREATE TABLE IF NOT EXISTS rate_buckets (
    bucket_key TEXT PRIMARY KEY,
    count      INTEGER NOT NULL,
    minute     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_minute ON rate_buckets(minute);
`)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func newToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Enroll claims a mailbox, or returns the existing claim.
//
// Idempotent for the same AID and key: an agent that re-enrolls after a restart
// should get its mailbox back, not a second one. A DIFFERENT key for an AID
// already here is refused — that is either a mistake or somebody trying to take
// over a mailbox, and neither should be handled by overwriting.
func (s *Store) Enroll(aid, publicKeyB64, oobi string) (*Enrollment, error) {
	now := time.Now().UTC()

	var existingKey, existingToken string
	err := s.db.QueryRow(
		`SELECT public_key_b64, deposit_token FROM enrollments WHERE aid = ?`, aid,
	).Scan(&existingKey, &existingToken)
	if err == nil {
		if existingKey != publicKeyB64 {
			return nil, fmt.Errorf("this AID is already enrolled with a different key")
		}
		s.db.Exec(`UPDATE enrollments SET last_seen_at = ? WHERE aid = ?`, now.Format(time.RFC3339), aid)
		return &Enrollment{
			AID: aid, PublicKeyB64: existingKey, OOBI: oobi,
			DepositToken: existingToken, LastSeenAt: now,
		}, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("look up enrollment: %w", err)
	}

	token, err := newToken()
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(
		`INSERT INTO enrollments (aid, public_key_b64, oobi, deposit_token, created_at, last_seen_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		aid, publicKeyB64, oobi, token, now.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	return &Enrollment{
		AID: aid, PublicKeyB64: publicKeyB64, OOBI: oobi,
		DepositToken: token, CreatedAt: now, LastSeenAt: now,
	}, nil
}

// EnrollmentByAID returns a claim, or nil.
func (s *Store) EnrollmentByAID(aid string) (*Enrollment, error) {
	return s.enrollmentWhere(`aid = ?`, aid)
}

// EnrollmentByToken resolves a deposit token to its owner.
//
// The token is what a sender presents, and it is capability-shaped on purpose:
// holding it lets you WRITE to a mailbox and nothing else. It cannot be used to
// read, and it does not reveal the AID to whoever holds it — they were given a
// URL to write to, not an identity to correlate.
func (s *Store) EnrollmentByToken(token string) (*Enrollment, error) {
	return s.enrollmentWhere(`deposit_token = ?`, token)
}

func (s *Store) enrollmentWhere(clause string, arg string) (*Enrollment, error) {
	var e Enrollment
	var created, lastSeen string
	err := s.db.QueryRow(
		`SELECT aid, public_key_b64, oobi, deposit_token, created_at, last_seen_at
		 FROM enrollments WHERE `+clause, arg,
	).Scan(&e.AID, &e.PublicKeyB64, &e.OOBI, &e.DepositToken, &created, &lastSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("look up enrollment: %w", err)
	}
	e.CreatedAt, _ = time.Parse(time.RFC3339, created)
	e.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeen)
	return &e, nil
}

// Deposit stores one envelope for an AID.
//
// The caller has already checked the size and the rate. What is enforced here
// is the standing total, because without it anybody can fill a stranger's
// mailbox until the operator runs out of disk or the owner cannot receive
// anything real.
func (s *Store) Deposit(aid string, envelope json.RawMessage, retention time.Duration,
	maxCount int, maxBytes int) (*Message, error) {

	var count, total int
	err := s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM messages WHERE aid = ?`, aid,
	).Scan(&count, &total)
	if err != nil {
		return nil, fmt.Errorf("check mailbox size: %w", err)
	}
	if count >= maxCount {
		return nil, fmt.Errorf("mailbox is full (%d waiting) — the recipient has not collected", count)
	}
	if total+len(envelope) > maxBytes {
		return nil, fmt.Errorf("mailbox is full (%d bytes waiting) — the recipient has not collected", total)
	}

	id, err := newToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := now.Add(retention)
	_, err = s.db.Exec(
		`INSERT INTO messages (id, aid, envelope, size_bytes, deposited_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, aid, []byte(envelope), len(envelope),
		now.Format(time.RFC3339), expires.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("deposit: %w", err)
	}
	return &Message{
		ID: id, AID: aid, SizeBytes: len(envelope),
		DepositedAt: now, ExpiresAt: expires,
	}, nil
}

// Collect returns waiting messages, oldest first, WITHOUT deleting them.
//
// Not deleting on read is the point. A collection that fails halfway would
// otherwise lose whatever had already been sent, with the sender believing it
// was delivered and the recipient never knowing it existed. The recipient
// acknowledges once the messages are safely elsewhere.
func (s *Store) Collect(aid string, limit int) ([]Message, bool, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, aid, envelope, size_bytes, deposited_at, expires_at
		 FROM messages WHERE aid = ? AND expires_at > ?
		 ORDER BY deposited_at ASC LIMIT ?`,
		aid, time.Now().UTC().Format(time.RFC3339), limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("collect: %w", err)
	}
	defer rows.Close()

	var out []Message
	for rows.Next() {
		var m Message
		var deposited, expires string
		if err := rows.Scan(&m.ID, &m.AID, &m.Envelope, &m.SizeBytes, &deposited, &expires); err != nil {
			return nil, false, fmt.Errorf("read message: %w", err)
		}
		m.DepositedAt, _ = time.Parse(time.RFC3339, deposited)
		m.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	// One extra was fetched to answer "is there more" without a second count.
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// Ack drops messages the recipient confirms it holds.
//
// Scoped to the AID as well as the ID so that knowing a message ID is not
// enough to delete somebody else's mail.
func (s *Store) Ack(aid string, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var dropped int
	for _, id := range ids {
		res, err := tx.Exec(`DELETE FROM messages WHERE id = ? AND aid = ?`, id, aid)
		if err != nil {
			return 0, fmt.Errorf("ack: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			dropped++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return dropped, nil
}

// Release gives up a mailbox and destroys what is in it.
func (s *Store) Release(aid string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM messages WHERE aid = ?`, aid); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM enrollments WHERE aid = ?`, aid); err != nil {
		return err
	}
	return tx.Commit()
}

// Sweep deletes expired messages and stale rate-limit buckets.
//
// Runs on a timer rather than only on access, so an abandoned mailbox is
// eventually emptied. Retention that only applies when somebody happens to look
// is not retention.
func (s *Store) Sweep() (int, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(`DELETE FROM messages WHERE expires_at <= ?`, now.Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("sweep messages: %w", err)
	}
	n, _ := res.RowsAffected()

	// Two minutes back rather than one, so a bucket in use right now is never
	// deleted out from under a request that is mid-flight.
	s.db.Exec(`DELETE FROM rate_buckets WHERE minute < ?`, now.Unix()/60-2)
	return int(n), nil
}

// Allow records one use against a rate-limit bucket and reports whether it is
// within the limit.
//
// Coarse minute buckets rather than a sliding window: cheap, good enough to
// stop abuse, and it keeps no history that could be read back as "who deposited
// when".
func (s *Store) Allow(key string, limit int) (bool, error) {
	minute := time.Now().UTC().Unix() / 60
	bucket := fmt.Sprintf("%s:%d", key, minute)

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var count int
	err = tx.QueryRow(`SELECT count FROM rate_buckets WHERE bucket_key = ?`, bucket).Scan(&count)
	if err == sql.ErrNoRows {
		if _, err := tx.Exec(
			`INSERT INTO rate_buckets (bucket_key, count, minute) VALUES (?, 1, ?)`,
			bucket, minute); err != nil {
			return false, err
		}
		return true, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	if count >= limit {
		// Not incremented past the limit: a caller hammering the endpoint
		// should not push its own counter higher and extend its own lockout.
		return false, tx.Commit()
	}
	if _, err := tx.Exec(
		`UPDATE rate_buckets SET count = count + 1 WHERE bucket_key = ?`, bucket); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// Stats reports totals, for an operator's own health checks. Deliberately
// aggregate: an operator should be able to see that the service is working
// without reading anybody's mailbox.
func (s *Store) Stats() (enrollments, messages, bytes int, err error) {
	s.db.QueryRow(`SELECT COUNT(*) FROM enrollments`).Scan(&enrollments)
	err = s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM messages`,
	).Scan(&messages, &bytes)
	return enrollments, messages, bytes, err
}
