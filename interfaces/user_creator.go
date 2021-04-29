package interfaces

import "github.com/steve-kaufman/go-auth-service/entities"

type UserCreator interface {
	CreateUser(entities.User) error
}
