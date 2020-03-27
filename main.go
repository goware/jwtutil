package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dgrijalva/jwt-go"
)

const VERSION = "v0.1.0"

var (
	flags = flag.NewFlagSet("jwtutil", flag.ExitOnError)

	fSecret = flags.String("secret", "", "JWT secret for encoding/decoding (be safe!!)")
	fEncode = flags.Bool("encode", false, "Encode new JWT token")
	fDecode = flags.Bool("decode", false, "Decode existing JWT token")
	fToken  = flags.String("token", "", "+decode, jwt token to decode")
	fExp    = flags.Int64("exp", -1, "+encode, set expiry claim (must be unix timestamp value)")
	fClaims = flags.String("claims", "", "+encode, set extra claims as json object")
)

func main() {
	flags.Parse(os.Args[1:])

	if len(os.Args) < 3 {
		fmt.Printf(usage, VERSION)
		os.Exit(1)
	}

	if *fSecret == "" && *fSecret != "<>" {
		fmt.Println("jwtutil: secret is empty.")
		return
	}

	if *fDecode {
		// Decode passed jwt token string
		if *fToken == "" {
			fmt.Println("-token flag cannot be empty.")
			return
		}

		token, err := jwt.Parse(*fToken, func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != "HS256" {
				log.Fatalf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(*fSecret), nil
		})
		fmt.Println("\nToken decoding details:")
		if err != nil {
			fmt.Printf(" * %v\n", err)
		}
		if !token.Valid {
			fmt.Println(" * Token is invalid!")
		} else {
			fmt.Println(" * Token is valid!")
		}

		fmt.Printf("\nToken claims:\n")
		claims, _ := token.Claims.(jwt.MapClaims)
		for k, v := range claims {
			fmt.Printf(" * %v: %+v\n", k, v)
		}
		fmt.Println()

		return
	}

	if *fEncode {
		// Encode new JWT token.
		token := jwt.New(jwt.GetSigningMethod("HS256"))

		claims := jwt.MapClaims{} // aka, map[string]interface{}
		if *fClaims != "" {
			err := json.Unmarshal([]byte(*fClaims), &claims)
			if err != nil {
				fmt.Println("Error! -claims flag is invalid json.", err)
				return
			}
		}

		if *fExp > 0 {
			claims["exp"] = *fExp
		}

		token.Claims = claims
		tokenStr, err := token.SignedString([]byte(*fSecret))
		if err != nil {
			log.Fatal(err)
		}

		fmt.Fprintln(os.Stderr)

		fmt.Println("Token:", tokenStr)

		fmt.Fprintf(os.Stderr, "\nClaims: %#v\n", claims)

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
