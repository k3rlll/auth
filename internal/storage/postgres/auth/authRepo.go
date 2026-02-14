package auth

import (
	"context"
	"main/domain/entity"
	metrics "main/internal/metrics"
	"main/pkg/customerrors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuthRepo struct {
	pool    *pgxpool.Pool
	Metrics *metrics.Metrics
}

func NewAuthRepo(pool *pgxpool.Pool, metrics *metrics.Metrics) *AuthRepo {
	return &AuthRepo{
		pool:    pool,
		Metrics: metrics,
	}
}

// CreateUser creates a new user in the database with the provided details and returns the user ID.
func (r *AuthRepo) CreateUser(ctx context.Context, userID uuid.UUID, email, username, passwordHash string) (uuid.UUID, error) {
	var err error
	defer func(start time.Time) {
		r.Metrics.ObserveDB("insert_user", start, err)
	}(time.Now())
	tag, err := r.pool.Exec(ctx, "INSERT INTO users (id, email, username, password_hash) VALUES ($1, $2, $3, $4)",
		userID, email, username, passwordHash)

	if err != nil {
		return uuid.Nil, err
	}
	if tag.RowsAffected() != 1 {
		err = customerrors.ErrNoTagsAffected
		return uuid.Nil, err
	}
	return userID, nil
}

// Returns userID and password hash
func (r *AuthRepo) GetUserByLogin(ctx context.Context, login string) (userID uuid.UUID, passwordHash string, err error) {

	defer func(start time.Time) {
		r.Metrics.ObserveDB("select_user_by_login", start, err)
	}(time.Now())

	err = r.pool.QueryRow(ctx, "select id, password_hash from users where username = $1 OR email = $1", login).Scan(
		&userID,
		&passwordHash,
	)
	if err != nil {
		return uuid.Nil, "", err
	}
	return userID, passwordHash, nil

}

// Saves the session associated with a user in the database, allowing for session management and token revocation.
func (r *AuthRepo) StoreSession(ctx context.Context, userID uuid.UUID, session entity.Session) (err error) {
	defer func(start time.Time) {
		r.Metrics.ObserveDB("insert_session", start, err)
	}(time.Now())
	sql := `INSERT INTO sessions 
			(id, user_id, refresh_token, created_at, expires_at, user_agent, ip_address) 
			VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err = r.pool.Exec(ctx,
		sql, session.ID, userID, session.RefreshToken, session.CreatedAt, session.ExpiresAt, session.UserAgent, session.ClientIP)

	return err

}

// DeleteSession removes a specific session for a user, effectively logging them out from that ONE SPECIFIC SESSION.
func (r *AuthRepo) DeleteSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	sql := `DELETE FROM sessions WHERE id = $1 AND user_id = $2`
	_, err := r.pool.Exec(ctx, sql, sessionID, userID)
	return err
}

// DeleteAllSessions removes all sessions for a user, effectively logging them out from !ALL! sessions.
func (r *AuthRepo) DeleteAllSessions(ctx context.Context, userID uuid.UUID) error {
	sql := `DELETE FROM sessions WHERE user_id = $1`
	_, err := r.pool.Exec(ctx, sql, userID)
	return err
}

func (r *AuthRepo) RefreshSession(ctx context.Context, session entity.Session) (err error) {

	defer func(start time.Time) {
		r.Metrics.ObserveDB("update_session", start, err)
	}(time.Now())

	sql := `UPDATE sessions SET created_at = $1, expires_at = $2, refresh_token = $3 WHERE id = $4 AND user_id = $5`
	_, err = r.pool.Exec(ctx, sql, session.CreatedAt, session.ExpiresAt, session.RefreshToken, session.ID, session.UserID)
	return err
}

// GetSessionByRefreshToken retrieves a session from the database based on the provided refresh token, allowing for session validation and management.
func (r *AuthRepo) GetSessionByRefreshToken(ctx context.Context, refreshToken uuid.UUID) (session entity.Session, err error) {
	defer func(start time.Time) {
		r.Metrics.ObserveDB("select_session_by_refresh_token", start, err)
	}(time.Now())

	sql := `SELECT id, user_id, created_at, expires_at, user_agent, ip_address
			FROM sessions WHERE refresh_token = $1`
	err = r.pool.QueryRow(ctx, sql, refreshToken).Scan(
		&session.ID,
		&session.UserID,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.UserAgent,
		&session.ClientIP,
	)
	return session, err

}

func (r *AuthRepo) UserIsBlocked(userID uuid.UUID) (bool, error) {
	var isBlocked bool
	err := r.pool.QueryRow(context.Background(),
		"SELECT is_blocked FROM users WHERE id = $1", userID).
		Scan(&isBlocked)
	if err != nil {
		return false, err
	}
	return !isBlocked, nil
}
