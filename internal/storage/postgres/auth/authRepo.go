package auth

import (
	"context"
	"main/domain/entity"
	"main/pkg/customerrors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuthRepo struct {
	pool *pgxpool.Pool
}

func NewAuthRepo(pool *pgxpool.Pool) *AuthRepo {
	return &AuthRepo{pool: pool}
}

// CreateUser creates a new user in the database with the provided details and returns the user ID.
func (r *AuthRepo) CreateUser(ctx context.Context, userID uuid.UUID, email, username, passwordHash string) (uuid.UUID, error) {
	tag, err := r.pool.Exec(ctx, "INSERT INTO users (id, email, username, password_hash) VALUES ($1, $2, $3, $4)",
		userID, email, username, passwordHash)
	if err != nil {
		return uuid.Nil, err
	}
	if tag.RowsAffected() != 1 {
		return uuid.Nil, customerrors.ErrNoTagsAffected
	}
	return userID, nil
}

// Returns userID and password hash
func (r *AuthRepo) GetUserByLogin(ctx context.Context, login string) (userID uuid.UUID, passwordHash string, err error) {
	err = r.pool.QueryRow(ctx, "select user_id, password_hash from users where (username OR email) VALUES($1) ", login).Scan(
		&userID,
		&passwordHash,
	)
	if err != nil {
		return uuid.Nil, "", err
	}
	return userID, passwordHash, nil

}

// Saves the session associated with a user in the database, allowing for session management and token revocation.
func (r *AuthRepo) StoreSession(ctx context.Context, userID uuid.UUID, session entity.Session) error {
	sql := `INSERT INTO sessions 
			(session_id, user_id, token, created_at, expires_at, user_agent, client_ip) 
			VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.pool.Exec(ctx,
		sql, session.ID, userID, session.RefreshToken, session.CreatedAt, session.ExpiresAt, session.UserAgent, session.ClientIP)
	return err

}

// DeleteSession removes a specific session for a user, effectively logging them out from that ONE SPECIFIC SESSION.
func (r *AuthRepo) DeleteSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	sql := `DELETE FROM sessions WHERE session_id = $1 AND user_id = $2`
	_, err := r.pool.Exec(ctx, sql, sessionID, userID)
	return err
}

// DeleteAllSessions removes all sessions for a user, effectively logging them out from !ALL! sessions.
func (r *AuthRepo) DeleteAllSessions(ctx context.Context, userID uuid.UUID) error {
	sql := `DELETE FROM sessions WHERE user_id = $1`
	_, err := r.pool.Exec(ctx, sql, userID)
	return err
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
