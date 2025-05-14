package internal

import "net/http"

// Not implemented yet
func somemiddleware(h http.HandlerFunc) http.HandlerFunc {
	// do something
	return func(rw http.ResponseWriter, r *http.Request) {
		// not implemented
		h(rw, r)
	}
}
