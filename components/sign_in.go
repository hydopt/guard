package components

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

//go:embed sign_in.html
var signInFiles embed.FS

var signInPage = mustRead(signInFiles, "sign_in.html")

var signInTemplate = template.Must(template.New("signin").Parse(signInPage))

func mustRead(fs embed.FS, name string) string {
	b, err := fs.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return string(b)
}

type Provider struct {
	Name      string
	Label     string
	StartPath string
}

func SignInHandler(providers []Provider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			Providers []Provider
		}{Providers: withNext(providers, r.URL.Query().Get("next"))}
		if err := signInTemplate.Execute(w, data); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})
}

// withNext copies providers and appends a same-origin next query to each
// start path so RequireLogin's /signin?next=… survives the click through to
// /auth/{provider}. Unsafe targets are dropped; handleStart still sanitizes.
func withNext(providers []Provider, next string) []Provider {
	next = strings.TrimSpace(next)
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return providers
	}
	out := make([]Provider, len(providers))
	for i, p := range providers {
		p.StartPath = appendQuery(p.StartPath, "next", next)
		out[i] = p
	}
	return out
}

func appendQuery(path, key, value string) string {
	u, err := url.Parse(path)
	if err != nil {
		return path
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}
