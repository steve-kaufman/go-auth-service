package interfaces

import "github.com/steve-kaufman/go-auth-service/entities"

type TokenGenerator interface {
	GenerateTokens(userID int, username string) (entities.LoginTokens, error)
}

type PasswordMatcher interface {
	MatchPassword(plainPass string, hashedPass string) (bool, error)
}

type PasswordHasher interface {
	HashPassword(password string) (string, error)
}
