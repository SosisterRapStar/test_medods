package core

import "time"

type User struct {
	Id string `json:"id"`
}

type Token struct {
	Id         string    `json:"-"`
	Content    string    `json:"content"`
	IssuedToIp string    `json:"-"`
	IssuedToUA string    `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
