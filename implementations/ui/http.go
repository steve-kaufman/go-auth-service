package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/steve-kaufman/go-auth-service/interfaces"
	"github.com/steve-kaufman/go-auth-service/usecases"
)

var ErrInvalidJSON = fmt.Errorf("invalid JSON")
var ErrNeedsUsername = fmt.Errorf("username is required")
var ErrNeedsPassword = fmt.Errorf("password is required")

var errCodesAndMessages = map[error]struct {
	code int
	msg  string
}{
	usecases.ErrInternal: {
		code: 500,
		msg:  "Internal error",
	},
	usecases.ErrNotFound: {
		code: 404,
		msg:  "User '%s' does not exist",
	},
	usecases.ErrBadPassword: {
		code: 400,
		msg:  "Incorrect password",
	},
	ErrNeedsUsername: {
		code: 400,
		msg:  "Username is required",
	},
	ErrNeedsPassword: {
		code: 400,
		msg:  "Password is required",
	},
	ErrInvalidJSON: {
		code: 400,
		msg:  "Invalid JSON",
	},
}

type HTTP struct {
	service interfaces.Service
}

func (server *HTTP) UseService(service interfaces.Service) {
	server.service = service
}

func (server HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/login" || r.URL.Path == "/signup" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		httpLogin(server.service, w, r)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func httpLogin(service interfaces.Service, w http.ResponseWriter, r *http.Request) {
	username, password, err := getUsernameAndPassword(r)
	if err != nil {
		sendError(w, err)
		return
	}

	tryLogin(w, service, username, password)
}

func getUsernameAndPassword(r *http.Request) (string, string, error) {
	body, err := getMapOfBody(r.Body)
	if err != nil {
		return "", "", err
	}
	username, isUsername := body["username"]
	if !isUsername {
		return "", "", ErrNeedsUsername
	}
	password, isPassword := body["password"]
	if !isPassword {
		return "", "", ErrNeedsPassword
	}
	return username, password, nil
}

func getMapOfBody(body io.ReadCloser) (map[string]string, error) {
	bodyBytes, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, usecases.ErrInternal
	}
	var mapOfBody map[string]string
	err = json.Unmarshal(bodyBytes, &mapOfBody)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	return mapOfBody, nil
}

func tryLogin(
	w http.ResponseWriter,
	service interfaces.Service, username string, password string,
) {
	tokens, err := service.Login(username, password)
	if err == usecases.ErrNotFound {
		sendError(w, err, username)
		return
	}
	if err != nil {
		sendError(w, err)
		return
	}
	json.NewEncoder(w).Encode(tokens)
}

func sendError(w http.ResponseWriter, err error, a ...interface{}) {
	errInfo, ok := errCodesAndMessages[err]
	if !ok {
		w.WriteHeader(500)
		fmt.Fprint(w, "Unexpected internal error")
		return
	}
	w.WriteHeader(errInfo.code)
	fmt.Fprintf(w, errInfo.msg, a...)
}
