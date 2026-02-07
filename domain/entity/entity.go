package entity

import "github.com/google/uuid"

// User represents a user in the system with essential attributes.
type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password"`
	CreatedAt    int64     `json:"created_at"`
	IsBlocked    bool      `json:"is_blocked"`
}

type UserSettings struct {
	UserID         uuid.UUID `json:"user_id"`
	PrivateAccount bool      `json:"private_account"`
	// Privacy indicates the user's privacy level (e.g., "public", "friends_only", "private").
	Privacy   string `json:"privacy"`
	CreatedAt int64  `json:"created_at"`
}

type Blacklist struct {
	UserID    uuid.UUID   `json:"user_id"`
	BlockedID []uuid.UUID `json:"blocked_id"`
}

type Profile struct {
	UserID    uuid.UUID `json:"user_id"`
	Gender    string    `json:"gender"`
	Age       int64     `json:"age"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	// Bio is a short biography or description of the user.
	Bio           string      `json:"bio"`
	Avatar        string      `json:"avatar"`
	Subscribers   []uuid.UUID `json:"subscribers"`
	Subscriptions []uuid.UUID `json:"subscriptions"`
	Posts         []uuid.UUID `json:"posts"`
	// Reposts is a list of post IDs that the user has reposted.
	Reposts []uuid.UUID `json:"reposts"`
	// Media is a list of media URLs associated with the user's profile.
	Media     []string `json:"media"`
	CreatedAt int64    `json:"created_at"`
}

// Post represents a social media post with various attributes.
type Post struct {
	// Unique identifier for the post
	ID uuid.UUID `json:"id"`
	// User ID of the author who created the post
	AuthorID uuid.UUID `json:"author_id"`
	// Description of the post
	Description string `json:"description"`
	// URL to the media associated with the post
	MediaURL string `json:"media_url"`
	// Count of likes the post has received
	Likes int64 `json:"likes"`
	// Count of reposts the post has received
	Reposts int64 `json:"reposts"`
	// Count of comments on the post
	Comments int64 `json:"comments"`
	// Timestamp when the post was created
	CreatedAt int64 `json:"created_at"`
	// Timestamp when the post was last updated
	UpdatedAt int64 `json:"updated_at"`
	// Indicates if the post contains video content
	Duration int64 `json:"duration"`
	IsVideo  bool  `json:"is_video"`
}

type Liked struct {
	PostID uuid.UUID `json:"post_id"`
	UserID uuid.UUID `json:"user_id"`
}

type Reposted struct {
	PostID    uuid.UUID `json:"post_id"`
	UserID    uuid.UUID `json:"user_id"`
	CreatedAt int64     `json:"created_at"`
}

type Comment struct {
	ID     uuid.UUID `json:"id"`
	PostID uuid.UUID `json:"post_id"`
	UserID uuid.UUID `json:"user_id"`
	// IsReply indicates whether the comment is a reply to another comment.
	IsReply bool `json:"is_reply"`
	// ReplyTo indicates the ID of the comment this comment is replying to, if applicable.
	ReplyTo   uuid.UUID `json:"reply_to"`
	Content   string    `json:"content"`
	Media     string    `json:"media"`
	CreatedAt int64     `json:"created_at"`
}

type Message struct {
	ID        uuid.UUID `json:"id"`
	SenderID  uuid.UUID `json:"sender_id"`
	ChatID    uuid.UUID `json:"chat_id"`
	Content   string    `json:"content"`
	Media     string    `json:"media"`
	CreatedAt int64     `json:"created_at"`
}

type Chat struct {
	ID        uuid.UUID   `json:"id"`
	Title     string      `json:"title"`
	Avatar    string      `json:"avatar"`
	Media     string      `json:"media"`
	UserIDs   []uuid.UUID `json:"user_ids"`
	Usernames []string    `json:"usernames"`
	CreatedAt int64       `json:"created_at"`
}

type ChatMember struct {
	ChatID   uuid.UUID `json:"chat_id"`
	UserID   uuid.UUID `json:"user_id"`
	JoinedAt int64     `json:"joined_at"`
}

type FollowRequest struct {
	ID        uuid.UUID `json:"id"`
	FromUser  uuid.UUID `json:"from_user"`
	ToUser    uuid.UUID `json:"to_user"`
	CreatedAt int64     `json:"created_at"`
}

type Session struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	RefreshToken uuid.UUID `json:"refresh_token"`
	IsBlocked    bool      `json:"is_blocked"`
	ClientIP     string    `json:"client_ip"`
	CreatedAt    int64     `json:"created_at"`
	ExpiresAt    int64     `json:"expires_at"`
	UserAgent    string    `json:"user_agent"`
}
