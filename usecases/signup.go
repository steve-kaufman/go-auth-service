package usecases

import (
	"github.com/steve-kaufman/go-auth-service/entities"
	"github.com/steve-kaufman/go-auth-service/interfaces"
)

type SignupDependencies struct {
	UserGetter  interfaces.UserGetter
	PassHasher  interfaces.PasswordHasher
	UserCreator interfaces.UserCreator
}

func Signup(
	deps SignupDependencies, username string, password string,
) error {
	err := checkUsernameIsUnique(deps.UserGetter, username)
	if err != nil {
		return err
	}

	hashedPass, err := hashPassword(deps.PassHasher, password)
	if err != nil {
		return err
	}

	return attemptCreateUser(deps.UserCreator, username, hashedPass)
}

func checkUsernameIsUnique(
	userGetter interfaces.UserGetter, username string,
) error {
	_, err := userGetter.GetUserByUsername(username)
	if err == nil {
		return ErrDuplicate
	}
	if err != ErrNotFound {
		return ErrInternal
	}
	return nil
}

func hashPassword(
	passHasher interfaces.PasswordHasher, password string,
) (string, error) {
	hashedPass, err := passHasher.HashPassword(password)
	if err != nil {
		return "", ErrInternal
	}
	return hashedPass, nil
}

func attemptCreateUser(
	userCreator interfaces.UserCreator, username string, hashedPass string,
) error {
	err := userCreator.CreateUser(entities.User{
		Username: username,
		Password: hashedPass,
	})
	if err != nil {
		return ErrInternal
	}
	return nil
}
