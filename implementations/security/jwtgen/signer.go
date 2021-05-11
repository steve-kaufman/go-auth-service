package jwtgen

import "github.com/dgrijalva/jwt-go"

type Token struct {
	Header map[string]interface{}
	Claims map[string]interface{}
	Secret string
}

type TokenSigner struct {
	secret     string
	timeGetter TimeGetter
}

func NewTokenSigner(secret string, timeGetter TimeGetter) *TokenSigner {
	signer := new(TokenSigner)
	signer.secret = secret
	signer.timeGetter = timeGetter
	return signer
}

func (signer TokenSigner) GetSignedToken(userID int, username string) (string, error) {
	return signToken(Token{
		Header: signer.getHeader(),
		Claims: signer.getClaimsFromUserInfo(userID, username),
		Secret: signer.secret,
	})
}

func (TokenSigner) getHeader() map[string]interface{} {
	return map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
}

func (signer TokenSigner) getClaimsFromUserInfo(
	userID int, username string,
) map[string]interface{} {
	return map[string]interface{}{
		"iat":      signer.timeGetter.GetTime(),
		"user_id":  userID,
		"username": username,
	}
}

func signToken(token Token) (string, error) {
	jwtObj := jwt.New(jwt.SigningMethodHS256)
	jwtObj.Header = token.Header
	jwtObj.Claims = jwt.MapClaims(token.Claims)
	return jwtObj.SignedString([]byte(token.Secret))
}
