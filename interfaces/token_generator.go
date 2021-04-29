package interfaces

import "github.com/steve-kaufman/go-auth-service/entities"

type TokenGenerator interface {
	GenerateTokens(userID int, username string) (entities.LoginTokens, error)
}
