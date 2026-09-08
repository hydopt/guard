package components

import (
	"embed"
	"html/template"
	"net/http"
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
		}{Providers: providers}
		if err := signInTemplate.Execute(w, data); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})
}
