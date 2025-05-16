package core

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	Id         uuid.UUID
	Name       string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastLogout *time.Time
}

type TokenInfo struct {
	UserId     uuid.UUID
	Id         uuid.UUID
	SignHash   string
	IssuedToUA string
	IssuedToIP string
	IsRevoked  bool
}

type Tokens struct {
	Access  string
	Refresh string
}
