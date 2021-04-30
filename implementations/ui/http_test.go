package ui_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/steve-kaufman/go-auth-service/entities"
	"github.com/steve-kaufman/go-auth-service/implementations/ui"
	"github.com/steve-kaufman/go-auth-service/interfaces"
	"github.com/steve-kaufman/go-auth-service/usecases"
)

var badPaths = []string{
	"/foo",
	"/bar/",
	"/foobar",
	"/foo/1/",
	"/bar/2",
	"/foobar/3",
	"/foo/bar",
}

func TestHTTP_Returns404_WithUnregisteredPath(t *testing.T) {
	for _, badPath := range badPaths {
		t.Run(badPath, func(t *testing.T) {
			reqURL := url.URL{
				Scheme: "https",
				Host:   "mywebsite.com",
				Path:   badPath,
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", reqURL.String(), nil)

			server := new(ui.HTTP)
			server.ServeHTTP(w, r)

			result := w.Result()
			if result.StatusCode != 404 {
				t.Fatalf("Expected 404; Got: %d", result.StatusCode)
			}
		})
	}
}

var allowedMethodsPerPath = map[string][]string{
	"/login":  {"POST"},
	"/signup": {"POST"},
}

var httpMethods = []string{
	http.MethodDelete,
	http.MethodGet,
	http.MethodHead,
	http.MethodOptions,
	http.MethodPatch,
	http.MethodPost,
	http.MethodPut,
}

func TestHTTP_Returns405_WithWrongHTTPMethods(t *testing.T) {
	for path, allowedMethods := range allowedMethodsPerPath {
		t.Run(path, func(t *testing.T) {
			for _, httpMethod := range httpMethods {
				if isStrInArr(httpMethod, allowedMethods) {
					continue
				}
				t.Run(httpMethod, func(t *testing.T) {
					reqURL := url.URL{
						Scheme: "https",
						Host:   "mywebsite.com",
						Path:   path,
					}

					w := httptest.NewRecorder()
					r := httptest.NewRequest(httpMethod, reqURL.String(), nil)

					server := new(ui.HTTP)
					server.ServeHTTP(w, r)

					result := w.Result()
					if result.StatusCode != http.StatusMethodNotAllowed {
						t.Fatalf("Expected status 405; Got: %d", result.StatusCode)
					}
				})
			}
		})
	}
}

func isStrInArr(str string, arr []string) bool {
	for _, item := range arr {
		if str == item {
			return true
		}
	}
	return false
}

type MockService struct {
	signedUpWithUsername string
	signedUpWithPassword string
}

func (s *MockService) Login(username string, password string) (entities.LoginTokens, error) {
	return entities.LoginTokens{
		AccessToken:  username + "foo",
		RefreshToken: password + "bar",
	}, nil
}

func (s *MockService) Signup(username string, password string) error {
	s.signedUpWithUsername = username
	s.signedUpWithPassword = password
	return nil
}

type BadService struct {
	err error
}

func NewBadService(err error) *BadService {
	s := new(BadService)
	s.err = err
	return s
}

func (s BadService) Login(username string, password string) (entities.LoginTokens, error) {
	return entities.LoginTokens{}, s.err
}

func (s BadService) Signup(username string, password string) error {
	return s.err
}

type BadBody struct {
	io.Closer
}

func (BadBody) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("foo")
}

type HTTPLoginTest struct {
	name string

	service   interfaces.Service
	inputBody interface{}

	expectedStatus  int
	expectedTokens  entities.LoginTokens
	expectedMessage string
}

var httpLoginTests = []HTTPLoginTest{
	{
		name: "Returns 500 with bad HTTP body",

		service:   new(MockService),
		inputBody: new(BadBody),

		expectedStatus:  500,
		expectedMessage: "Internal error",
	},
	{
		name: "Returns 400 with bad JSON",

		service:   new(MockService),
		inputBody: bytes.NewBufferString("invalid JSON"),

		expectedStatus:  400,
		expectedMessage: "Invalid JSON",
	},
	{
		name: "No username or password",

		service:   new(MockService),
		inputBody: map[string]string{},

		expectedStatus:  400,
		expectedMessage: "Username is required",
	},
	{
		name: "Username but no password",

		service: new(MockService),
		inputBody: map[string]string{
			"username": "johndoe",
		},

		expectedStatus:  400,
		expectedMessage: "Password is required",
	},
	{
		name: "Returns 500 when Service returns ErrInternal",

		service: NewBadService(usecases.ErrInternal),
		inputBody: map[string]string{
			"username": "johndoe",
			"password": "supersecret",
		},

		expectedStatus:  500,
		expectedMessage: "Internal error",
	},
	{
		name: "Returns 404 when Service returns ErrNotFound",

		service: NewBadService(usecases.ErrNotFound),
		inputBody: map[string]string{
			"username": "johndoe",
			"password": "supersecret",
		},

		expectedStatus:  404,
		expectedMessage: "User 'johndoe' does not exist",
	},
	{
		name: "Returns 400 when Service returns ErrBadPassword",

		service: NewBadService(usecases.ErrBadPassword),
		inputBody: map[string]string{
			"username": "johndoe",
			"password": "supersecret",
		},

		expectedStatus:  400,
		expectedMessage: "Incorrect password",
	},
	{
		name: "Returns 500 when Service returns unknown error",

		service: NewBadService(fmt.Errorf("foo")),
		inputBody: map[string]string{
			"username": "johndoe",
			"password": "supersecret",
		},

		expectedStatus:  500,
		expectedMessage: "Unexpected internal error",
	},
	{
		name: "Returns expected access and refresh tokens",

		service: new(MockService),
		inputBody: map[string]string{
			"username": "johndoe",
			"password": "supersecret",
		},

		expectedStatus: 200,
		expectedTokens: entities.LoginTokens{
			AccessToken:  "johndoefoo",
			RefreshToken: "supersecretbar",
		},
	},
}

func TestHTTP_LoginRoute(t *testing.T) {
	for _, tc := range httpLoginTests {
		t.Run(tc.name, func(t *testing.T) {
			body := getBodyFromTC(tc)

			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "http://mywebsite.com/login", body)

			server := new(ui.HTTP)
			server.UseService(tc.service)
			server.ServeHTTP(w, r)

			result := w.Result()
			if result.StatusCode != tc.expectedStatus {
				t.Fatalf("Expected status: %d; Got: %d",
					tc.expectedStatus, result.StatusCode)
			}

			if (tc.expectedTokens != entities.LoginTokens{}) {
				var tokens entities.LoginTokens
				json.NewDecoder(result.Body).Decode(&tokens)
				expectTokensToMatch(t, tc.expectedTokens, tokens)
				return
			}

			if body := w.Body.String(); body != tc.expectedMessage {
				t.Fatalf("Expected error message: '%s'; Got: '%s'", tc.expectedMessage, body)
			}
		})
	}
}

func getBodyFromTC(tc HTTPLoginTest) io.Reader {
	if reader, ok := tc.inputBody.(io.Reader); ok {
		return reader
	}
	body := new(bytes.Buffer)
	json.NewEncoder(body).Encode(tc.inputBody)
	return body
}

func expectTokensToMatch(
	t *testing.T,
	expectedTokens entities.LoginTokens,
	receivedTokens entities.LoginTokens,
) {
	diff := cmp.Diff(expectedTokens, receivedTokens)
	if diff != "" {
		t.Fatalf("Expected tokens to match: \n%s", diff)
	}
}
