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
			if err != nil {
				fmt.Fprintf(stderr, "\nERROR: Can't verify token: %v\n", err)
			} else {
				fmt.Fprintln(stderr, "\nToken decoding details:")
				if err := jwt.Validate(token); err != nil {
					fmt.Fprintf(stderr, " * Token is invalid: %v\n", err)
				} else {
					fmt.Fprintln(stderr, " * Token is valid!")
				}
			}
		} else {
			fmt.Fprintln(stderr, "\nWARNING: No -secret flag provided. Can't verify token.")
		}

		if token == nil {
			token, err = jwt.Parse([]byte(*fToken), jwt.WithVerify(false))
			if err != nil {
				fmt.Fprintf(stderr, "\nERROR: Can't parse token: %v\n", err)
				os.Exit(1)
			}
		}

		claims, _ := token.AsMap(context.Background())
		printClaims(stderr, claims)

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

		fmt.Fprintf(stderr, "\nToken: ")
		fmt.Printf("%s", tokenStr)
		fmt.Fprintln(stderr)

		claims, _ = token.AsMap(context.Background())
		printClaims(stderr, claims)

		return
	}
}

// An improved version of fmt.Sprintf("%#v", claims) with newlines.
func printClaims(stderr io.Writer, claims map[string]interface{}) {
	fmt.Fprintln(stderr, "\nClaims: map[string]interface{}{")

	// Sort keys for stable output
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}

	for _, k := range keys {
		fmt.Fprintf(stderr, "    %q: %#v,\n", k, claims[k])
	}
	fmt.Fprintln(stderr, "}")
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
