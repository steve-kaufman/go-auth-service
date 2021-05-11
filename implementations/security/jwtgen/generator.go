package jwtgen

import (
	"github.com/steve-kaufman/go-auth-service/entities"
)

type Secrets struct {
	Access  string
	Refresh string
}

type Generator struct {
	accessSigner  *TokenSigner
	refreshSigner *TokenSigner
}

func NewGenerator(secrets Secrets, timeGetter TimeGetter) *Generator {
	generator := new(Generator)
	generator.accessSigner = NewTokenSigner(secrets.Access, timeGetter)
	generator.refreshSigner = NewTokenSigner(secrets.Refresh, timeGetter)
	return generator
}

func (generator Generator) GetTokens(
	userID int, username string,
) (entities.LoginTokens, error) {
	accessToken, err := generator.accessSigner.GetSignedToken(userID, username)
	if err != nil {
		return entities.LoginTokens{}, err
	}
	refreshToken, err := generator.refreshSigner.GetSignedToken(userID, username)
	if err != nil {
		return entities.LoginTokens{}, err
	}

	return entities.LoginTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
