package usecases

import "errors"

var ErrInternal = errors.New("internal error")
var ErrNotFound = errors.New("user not found")
var ErrBadPassword = errors.New("incorrect password")
var ErrDuplicate = errors.New("duplicate username")
