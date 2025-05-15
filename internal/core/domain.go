package core

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	Id         string
	LastLogout time.Time
}

type TokenInfo struct {
	UserId     uuid.UUID
	Id         uuid.UUID
	SignHash   string
	IssuedToUA string
	IssuedToIP string
	IsRevoked  bool
}
