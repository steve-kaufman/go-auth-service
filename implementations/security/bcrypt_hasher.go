package security

import "golang.org/x/crypto/bcrypt"

type BcryptHasher struct{}

func (BcryptHasher) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(hash), err
}

func (BcryptHasher) MatchPassword(plainPass string, hashedPass string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(plainPass))
	return err == nil, err
}
