package usecases_test

import (
	"errors"
	"testing"

	"github.com/steve-kaufman/go-auth-service/entities"
	"github.com/steve-kaufman/go-auth-service/interfaces"
	"github.com/steve-kaufman/go-auth-service/usecases"
)

func mockHash(str string) string {
	return str + "foo"
}

var exampleUsers = []entities.User{
	{
		ID:       1,
		Username: "user1",
		Password: mockHash("pass1"),
	},
	{
		ID:       2,
		Username: "user2",
		Password: mockHash("pass2"),
	},
	{
		ID:       3,
		Username: "user3",
		Password: mockHash("pass3"),
	},
}

type MockUserGetter struct{}

func (MockUserGetter) GetUserByUsername(username string) (entities.User, error) {
	for _, user := range exampleUsers {
		if user.Username == username {
			return user, nil
		}
	}
	return entities.User{}, usecases.ErrNotFound
}

type BadUserGetter struct{}

func (BadUserGetter) GetUserByUsername(username string) (entities.User, error) {
	return entities.User{}, errors.New("foo")
}

type MockPasswordMatcher struct{}

func (MockPasswordMatcher) MatchPassword(
	plainPass string, hashedPass string,
) (bool, error) {
	if mockHash(plainPass) == hashedPass {
		return true, nil
	}
	return false, nil
}

type BadPasswordMatcher struct{}

func (BadPasswordMatcher) MatchPassword(
	plainPass string, hashedPass string,
) (bool, error) {
	return false, errors.New("bar")
}

type MockTokenGenerator struct{}

func (MockTokenGenerator) GetTokens(
	userID int, username string,
) (entities.LoginTokens, error) {
	return entities.LoginTokens{
		AccessToken:  "access.token.foo",
		RefreshToken: "refresh.token.bar",
	}, nil
}

type BadTokenGenerator struct{}

func (BadTokenGenerator) GetTokens(
	userID int, username string,
) (entities.LoginTokens, error) {
	return entities.LoginTokens{}, errors.New("foobar")
}

type LoginTest struct {
	name string

	userGetter     interfaces.UserGetter
	passMatcher    interfaces.PasswordMatcher
	tokenGenerator interfaces.TokenGenerator
	inputUsername  string
	inputPassword  string

	expectedErr    error
	expectedTokens entities.LoginTokens
}

var loginTests = []LoginTest{
	{
		name: "Returns ErrInternal with bad UserGetter",

		userGetter:     new(BadUserGetter),
		passMatcher:    new(MockPasswordMatcher),
		tokenGenerator: new(MockTokenGenerator),
		inputUsername:  "user1",
		inputPassword:  "pass1",

		expectedErr:    usecases.ErrInternal,
		expectedTokens: entities.LoginTokens{},
	},
	{
		name: "Returns ErrInternal with bad PassMatcher",

		userGetter:     new(MockUserGetter),
		passMatcher:    new(BadPasswordMatcher),
		tokenGenerator: new(MockTokenGenerator),
		inputUsername:  "user1",
		inputPassword:  "pass1",

		expectedErr:    usecases.ErrInternal,
		expectedTokens: entities.LoginTokens{},
	},
	{
		name: "Returns ErrInternal with bad TokenGenerator",

		userGetter:     new(MockUserGetter),
		passMatcher:    new(MockPasswordMatcher),
		tokenGenerator: new(BadTokenGenerator),
		inputUsername:  "user1",
		inputPassword:  "pass1",

		expectedErr:    usecases.ErrInternal,
		expectedTokens: entities.LoginTokens{},
	},
	{
		name: "Returns ErrNotFound when UserGetter returns ErrNotFound",

		userGetter:     new(MockUserGetter),
		passMatcher:    new(MockPasswordMatcher),
		tokenGenerator: new(MockTokenGenerator),
		inputUsername:  "non.existant.user",
		inputPassword:  "supersecret",

		expectedErr:    usecases.ErrNotFound,
		expectedTokens: entities.LoginTokens{},
	},
	{
		name: "Returns ErrBadPassword when PasswordMatcher returns false",

		userGetter:     new(MockUserGetter),
		passMatcher:    new(MockPasswordMatcher),
		tokenGenerator: new(MockTokenGenerator),
		inputUsername:  "user2",
		inputPassword:  "wrongpassword",

		expectedErr:    usecases.ErrBadPassword,
		expectedTokens: entities.LoginTokens{},
	},
	{
		name: "Returns tokens from TokenGenerator",

		userGetter:     new(MockUserGetter),
		passMatcher:    new(MockPasswordMatcher),
		tokenGenerator: new(MockTokenGenerator),
		inputUsername:  "user2",
		inputPassword:  "pass2",

		expectedErr: nil,
		expectedTokens: entities.LoginTokens{
			AccessToken:  "access.token.foo",
			RefreshToken: "refresh.token.bar",
		},
	},
}

func TestLogin(t *testing.T) {
	for _, tc := range loginTests {
		t.Run(tc.name, func(t *testing.T) {
			deps := usecases.LoginDependencies{
				UserGetter:     tc.userGetter,
				PassMatcher:    tc.passMatcher,
				TokenGenerator: tc.tokenGenerator,
			}

			tokens, err := usecases.Login(deps, tc.inputUsername, tc.inputPassword)

			if err != tc.expectedErr {
				t.Fatalf("Expected err: '%v'; Got: '%v'", tc.expectedErr, err)
			}

			if tokens.AccessToken != tc.expectedTokens.AccessToken {
				t.Fatalf("Expected access token: '%s'; Got: '%s'",
					tokens.AccessToken, tc.expectedTokens.AccessToken)
			}
			if tokens.RefreshToken != tc.expectedTokens.RefreshToken {
				t.Fatalf("Expected refresh token: '%s'; Got: '%s'",
					tokens.RefreshToken, tc.expectedTokens.RefreshToken)
			}
		})
	}
}
