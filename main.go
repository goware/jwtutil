package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	VERSION = ""

	flags   = flag.NewFlagSet("jwtutil", flag.ExitOnError)
	fSecret = flags.String("secret", "", "JWT secret for encoding/decoding (be safe!!)")
	fSilent = flags.Bool("silent", false, "Silent mode. Print JWT token only")
	fEncode = flags.Bool("encode", false, "Encode new JWT token")
	fDecode = flags.Bool("decode", false, "Decode existing JWT token")
	fToken  = flags.String("token", "", "+decode, jwt token to decode")
	fExp    = flags.Int64("exp", -1, "+encode, set expiry claim (must be unix timestamp value)")
	fClaims = flags.String("claims", "", "+encode, set extra claims as json object")
)

func main() {
	flags.Parse(os.Args[1:])

	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, usage, VERSION)
		os.Exit(1)
	}

	var stderr io.Writer = os.Stderr
	if *fSilent {
		stderr = io.Discard
	}

	if *fDecode {
		// Decode passed jwt token string
		if *fToken == "" {
			fmt.Fprintln(stderr, "-token flag cannot be empty.")
			return
		}

		var token jwt.Token
		var err error

		if *fSecret != "" {
			token, err = jwt.Parse([]byte(*fToken), jwt.WithKey(jwa.HS256, []byte(*fSecret)))
		} else {
			token, err = jwt.Parse([]byte(*fToken))
		}

		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(stderr, "\nToken decoding details:")

		if *fSecret != "" {
			if err := jwt.Validate(token); err != nil {
				fmt.Fprintln(stderr, " * Token is invalid!")
			} else {
				fmt.Fprintln(stderr, " * Token is valid!")
			}
		}

		fmt.Fprintf(stderr, "\nToken claims:\n")
		claims, _ := token.AsMap(context.Background())
		for k, v := range claims {
			fmt.Fprintf(stderr, " * %v: %+v\n", k, v)
		}
		fmt.Fprintln(stderr)

		return
	}

	if *fSecret == "" && *fSecret != "<>" {
		fmt.Fprintln(stderr, "jwtutil: secret is empty.")
		return
	}

	if *fEncode {
		// Encode new JWT token.
		token := jwt.New()

		var claims map[string]interface{}
		if *fClaims != "" {
			err := json.Unmarshal([]byte(*fClaims), &claims)
			if err != nil {
				fmt.Fprintln(stderr, "Error! -claims flag is invalid json.", err)
				return
			}
		}
		for k, v := range claims {
			err := token.Set(k, v)
			if err != nil {
				log.Fatal(err)
			}
		}

		if *fExp > 0 {
			token.Set("exp", *fExp)
		}

		tokenPayload, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte(*fSecret)))
		if err != nil {
			log.Fatal(err)
		}
		tokenStr := string(tokenPayload)

		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Token:", tokenStr)
		fmt.Printf("%s", tokenStr)

		claims, _ = token.AsMap(context.Background())
		fmt.Fprintf(stderr, "\n\nClaims: %#v\n", claims)
		fmt.Fprintln(stderr)

		return
	}
}

var usage = `jwtutil %s

usage:

# New JWT token
$ jwtutil -secret=besafe -encode

# New JWT token with expiry (unix timestamp value)
$ jwtutil -secret=besafe -encode -exp=1585272657

# New JWT token with custom claims
$ jwtutil -secret=besafe -encode -claims='{"account":1234}'

# Decode JWT
$ jwtutil -secret=besafe -decode -token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50IjoxMjM0fQ.WrPyTSoovFETG6pW0wFepaAv9-VTIfeSHU5imhPqs7g'

`
