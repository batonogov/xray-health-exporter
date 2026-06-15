package main

import (
	"crypto/subtle"
	"net/http"
)

// basicAuthMiddleware wraps the next handler with HTTP Basic Auth.
// Credentials are compared in constant time via crypto/subtle to mitigate
// timing attacks. On failure it responds 401 with a WWW-Authenticate header
// so Prometheus (and browsers) can supply credentials on the next request.
func basicAuthMiddleware(username, password string, next http.Handler) http.Handler {
	expectedUser := []byte(username)
	expectedPass := []byte(password)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		// Compare both credentials unconditionally so the response time does not
		// leak whether the username was correct. subtle.ConstantTimeCompare is
		// constant in its inputs, but only when it is actually invoked; a short-
		// circuited || would skip the password check on a username mismatch,
		// creating a timing oracle for username enumeration. When ok is false,
		// u and p are empty strings, so the comparisons remain safe to run.
		userOK := subtle.ConstantTimeCompare([]byte(u), expectedUser)
		passOK := subtle.ConstantTimeCompare([]byte(p), expectedPass)
		if !ok || userOK != 1 || passOK != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
