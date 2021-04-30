package interfaces

import "github.com/steve-kaufman/go-auth-service/entities"

type Service interface {
	Login(username string, password string) (entities.LoginTokens, error)
	Signup(username string, password string) error
}
