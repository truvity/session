// echo is the upstream: it returns the request headers it received.
package main

import (
	"encoding/json"
	"net/http"
	"os"
)

func main() {
	addr := "127.0.0.1:18095"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"method": r.Method, "path": r.URL.RequestURI(), "host": r.Host, "headers": r.Header})
	}))
}
