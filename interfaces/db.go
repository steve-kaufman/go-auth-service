package interfaces

import "github.com/steve-kaufman/go-auth-service/entities"

type UserGetter interface {
	GetUserByUsername(username string) (entities.User, error)
}

type UserCreator interface {
	CreateUser(entities.User) error
}
