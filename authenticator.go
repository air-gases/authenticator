package authenticator

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aofei/air"
)

// BasicAuthGasConfig is a set of configurations for the `BasicAuthGas`.
type BasicAuthGasConfig struct {
	PasswordProvider func(username string) string
	ErrUnauthorized  error

	Skippable func(*air.Request, *air.Response) bool
}

// BasicAuthGas returns an `air.Gas` that is used to authenticate ervery request
// by using the HTTP Basic Authentication (See RFC 2617, Section 2) based on the
// bagc. It prevents unauthenticated clients from accessing server resources.
func BasicAuthGas(bagc BasicAuthGasConfig) air.Gas {
	if bagc.PasswordProvider == nil {
		bagc.PasswordProvider = func(_ string) string {
			return ""
		}
	}

	if bagc.ErrUnauthorized == nil {
		bagc.ErrUnauthorized = errors.New(
			http.StatusText(http.StatusUnauthorized),
		)
	}

	return func(next air.Handler) air.Handler {
		return func(req *air.Request, res *air.Response) error {
			if bagc.Skippable != nil && bagc.Skippable(req, res) {
				return next(req, res)
			}

			authHeader := req.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Basic ") {
				res.Status = http.StatusUnauthorized
				return bagc.ErrUnauthorized
			}

			b, _ := base64.StdEncoding.DecodeString(authHeader[6:])
			authParts := strings.SplitN(string(b), ":", 2)
			if len(authParts) != 2 ||
				authParts[0] == "" ||
				authParts[1] == "" {
				res.Status = http.StatusUnauthorized
				return bagc.ErrUnauthorized
			}

			if bagc.PasswordProvider(authParts[0]) != authParts[1] {
				time.Sleep(3 * time.Second)
				res.Status = http.StatusUnauthorized
				return bagc.ErrUnauthorized
			}

			return next(req, res)
		}
	}
}
