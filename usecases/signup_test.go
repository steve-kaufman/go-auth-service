package usecases_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/steve-kaufman/go-auth-service/entities"
	"github.com/steve-kaufman/go-auth-service/interfaces"
	"github.com/steve-kaufman/go-auth-service/usecases"
)

type MockPasswordHasher struct{}

func (MockPasswordHasher) HashPassword(password string) (string, error) {
	return password + "foo", nil
}

type BadPasswordHasher struct{}

func (BadPasswordHasher) HashPassword(password string) (string, error) {
	return "", fmt.Errorf("something went wrong")
}

type MockUserCreator struct {
	createdUser entities.User
}

func (uc *MockUserCreator) CreateUser(user entities.User) error {
	user.ID = 7
	uc.createdUser = user
	return nil
}

type BadUserCreator struct{}

func (BadUserCreator) CreateUser(user entities.User) error {
	return fmt.Errorf("something went wrong")
}

type SignupTest struct {
	name string

	userGetter  interfaces.UserGetter
	passHasher  interfaces.PasswordHasher
	userCreator interfaces.UserCreator

	inputUsername string
	inputPassword string

	expectedErr         error
	expectedCreatedUser entities.User
}

var signupTests = []SignupTest{
	{
		name: "Returs ErrInternal with bad UserGetter",

		userGetter:  new(BadUserGetter),
		passHasher:  new(MockPasswordHasher),
		userCreator: new(MockUserCreator),

		inputUsername: "newuser",
		inputPassword: "supersecret",

		expectedErr: usecases.ErrInternal,
	},
	{
		name: "Returs ErrDuplicate with already existing username",

		userGetter:  new(MockUserGetter),
		passHasher:  new(MockPasswordHasher),
		userCreator: new(MockUserCreator),

		inputUsername: "user1",
		inputPassword: "supersecret",

		expectedErr: usecases.ErrDuplicate,
	},
	{
		name: "Succeeds with good UserGetter and new username",

		userGetter:  new(MockUserGetter),
		passHasher:  new(MockPasswordHasher),
		userCreator: new(MockUserCreator),

		inputUsername: "newuser",
		inputPassword: "supersecret",

		expectedErr: nil,
		expectedCreatedUser: entities.User{
			ID:       7,
			Username: "newuser",
			Password: "supersecretfoo",
		},
	},
	{
		name: "Returns ErrInternal with bad PasswordHasher",

		userGetter:  new(MockUserGetter),
		passHasher:  new(BadPasswordHasher),
		userCreator: new(MockUserCreator),

		inputUsername: "newuser",
		inputPassword: "supersecret",

		expectedErr: usecases.ErrInternal,
	},
	{
		name: "Returns ErrInternal with bad UserCreator",

		userGetter:  new(MockUserGetter),
		passHasher:  new(MockPasswordHasher),
		userCreator: new(BadUserCreator),

		inputUsername: "newuser",
		inputPassword: "supersecret",

		expectedErr: usecases.ErrInternal,
	},
}

func TestSignup(t *testing.T) {
	for _, tc := range signupTests {
		t.Run(tc.name, func(t *testing.T) {
			deps := usecases.SignupDependencies{
				UserGetter:  tc.userGetter,
				PassHasher:  tc.passHasher,
				UserCreator: tc.userCreator,
			}

			err := usecases.Signup(deps, tc.inputUsername, tc.inputPassword)
			if err != tc.expectedErr {
				t.Fatalf("Expected err: '%v'; Got: '%v'", tc.expectedErr, err)
			}

			mockUserCreator, ok := tc.userCreator.(*MockUserCreator)
			if !ok {
				return
			}
			if diff := cmp.Diff(tc.expectedCreatedUser, mockUserCreator.createdUser); diff != "" {
				t.Fatalf("Expected user to be created: \n%s", diff)
			}
		})
	}
}
