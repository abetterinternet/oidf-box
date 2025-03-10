package errors

import (
	"github.com/go-errors/errors"
)

// Error wraps an errors.Error with an implementation of error.Error() that always prints out the
// stack trace.
// The intent is for this type to only be used when errors are originated. Any circumstance where
// an error is being wrapped and passed up the stack can just use the `%w` formatter.
// TODO: it might be nice to restrict this to test builds, but currently this project is *only* used
// in tests and it's very convenient for debugging to get a backtrace of where errors originated.
type Error struct {
	error errors.Error
}

// Errorf creates a new error with the given message.
func Errorf(format string, a ...interface{}) *Error {
	return &Error{error: *errors.Errorf(format, a...)}
}

// Error returns the underlying error's message and stack trace.
func (e *Error) Error() string {
	return e.error.ErrorStack()
}
