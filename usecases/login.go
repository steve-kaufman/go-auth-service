package usecases

import (
	"github.com/steve-kaufman/go-auth-service/entities"
	"github.com/steve-kaufman/go-auth-service/interfaces"
)

type LoginDependencies struct {
	UserGetter     interfaces.UserGetter
	PassMatcher    interfaces.PasswordMatcher
	TokenGenerator interfaces.TokenGenerator
}

func Login(
	deps LoginDependencies, username string, password string,
) (entities.LoginTokens, error) {
	user, err := getUser(deps.UserGetter, username)
	if err != nil {
		return entities.LoginTokens{}, err
	}
	err = verifyPassword(deps.PassMatcher, password, user)
	if err != nil {
		return entities.LoginTokens{}, err
	}
	return generateTokens(deps.TokenGenerator, user)
}

func getUser(
	userGetter interfaces.UserGetter, username string,
) (entities.User, error) {
	user, err := userGetter.GetUserByUsername(username)
	if err == ErrNotFound {
		return entities.User{}, ErrNotFound
	}
	if err != nil {
		return entities.User{}, ErrInternal
	}
	return user, nil
}

func verifyPassword(
	passMatcher interfaces.PasswordMatcher, password string, user entities.User,
) error {
	passwordIsGood, err := passMatcher.MatchPassword(password, user.Password)
	if err != nil {
		return ErrInternal
	}
	if !passwordIsGood {
		return ErrBadPassword
	}
	return nil
}

func generateTokens(
	tokenGenerator interfaces.TokenGenerator, user entities.User,
) (entities.LoginTokens, error) {
	tokens, err := tokenGenerator.GenerateTokens(user.ID, user.Username)
	if err != nil {
		return entities.LoginTokens{}, ErrInternal
	}
	return tokens, nil
}
