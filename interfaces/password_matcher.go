package interfaces

type PasswordMatcher interface {
	MatchPassword(plainPass string, hashedPass string) (bool, error)
}
