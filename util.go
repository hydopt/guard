package guard

import "net/http"

const (
	HxRequest  = "HX-Request"
	HxRedirect = "HX-Redirect"
)

func Assert(cond bool, msg string) {
	if !cond {
		panic(msg)
	}
}

func Redirect(w http.ResponseWriter, r *http.Request, url string, code int) {
	if r.Header.Get(HxRequest) != "" {
		w.Header().Set(HxRedirect, url)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, url, code)
}
