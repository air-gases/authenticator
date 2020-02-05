package authenticator

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aofei/air"
)

// BasicAuthGasConfig is a set of configurations for the `BasicAuthGas`.
type BasicAuthGasConfig struct {
	Validator       func(username, password string, req *air.Request, res *air.Response) (bool, error)
	Realm           string
	ErrUnauthorized error

	Skippable func(*air.Request, *air.Response) bool
}

// BasicAuthGas returns an `air.Gas` that is used to authenticate ervery request
// by using the HTTP Basic Authentication (See RFC 2617, Section 2) based on the
// bagc. It prevents unauthenticated clients from accessing server resources.
func BasicAuthGas(bagc BasicAuthGasConfig) air.Gas {
	if bagc.Validator == nil {
		bagc.Validator = func(
			_ string,
			_ string,
			_ *air.Request,
			_ *air.Response,
		) (bool, error) {
			return false, nil
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
			if len(authHeader) < 6 ||
				!strings.EqualFold(authHeader[:6], "Basic ") {
				res.Status = http.StatusUnauthorized
				if bagc.Realm != "" {
					res.Header.Set(
						"WWW-Authenticate",
						fmt.Sprintf(
							"Basic realm=%q",
							bagc.Realm,
						),
					)
				}

				return bagc.ErrUnauthorized
			}

			b, _ := base64.StdEncoding.DecodeString(authHeader[6:])
			authParts := strings.SplitN(string(b), ":", 2)
			if len(authParts) != 2 ||
				authParts[0] == "" ||
				authParts[1] == "" {
				res.Status = http.StatusUnauthorized
				if bagc.Realm != "" {
					res.Header.Set(
						"WWW-Authenticate",
						fmt.Sprintf(
							"Basic realm=%q",
							bagc.Realm,
						),
					)
				}

				return bagc.ErrUnauthorized
			}

			authorized, err := bagc.Validator(
				authParts[0],
				authParts[1],
				req,
				res,
			)
			if err != nil {
				return err
			}

			if !authorized {
				time.Sleep(3 * time.Second)

				res.Status = http.StatusUnauthorized
				if bagc.Realm != "" {
					res.Header.Set(
						"WWW-Authenticate",
						fmt.Sprintf(
							"Basic realm=%q",
							bagc.Realm,
						),
					)
				}

				return bagc.ErrUnauthorized
			}

			return next(req, res)
		}
	}
}
