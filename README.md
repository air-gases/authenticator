# Authenticator

[![GoDoc](https://godoc.org/github.com/air-gases/authenticator?status.svg)](https://godoc.org/github.com/air-gases/authenticator)

A useful gas that used to authenticate every request for the web applications
built using [Air](https://github.com/aofei/air).

## Installation

Open your terminal and execute

```bash
$ go get github.com/air-gases/authenticator
```

done.

> The only requirement is the [Go](https://golang.org), at least v1.13.

## Usage

The following application will require all home requests to carry an HTTP Basic
Authentication (See RFC 2617, Section 2) header with the username part is "foo"
and password part is "bar".

```go
package main

import (
	"github.com/air-gases/authenticator"
	"github.com/aofei/air"
)

func main() {
	a := air.Default
	a.DebugMode = true
	a.GET("/", func(req *air.Request, res *air.Response) error {
		return res.WriteString("You are authorized!")
	}, authenticator.BasicAuthGas(authenticator.BasicAuthGasConfig{
		Validator: func(
				username string,
				password string,
				_ *air.Request,
				_ *air.Response,
		) (bool, error) {
			return username == "foo" && password == "bar", nil
		},
	}))
	a.Serve()
}
```

## Community

If you want to discuss Authenticator, or ask questions about it, simply post
questions or ideas [here](https://github.com/air-gases/authenticator/issues).

## Contributing

If you want to help build Authenticator, simply follow
[this](https://github.com/air-gases/authenticator/wiki/Contributing) to send
pull requests [here](https://github.com/air-gases/authenticator/pulls).

## License

This project is licensed under the Unlicense.

License can be found [here](LICENSE).
