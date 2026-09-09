package components

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed basic_auth_login.html
var basicAuthLoginFiles embed.FS

var basicAuthLoginPage = mustRead(basicAuthLoginFiles, "basic_auth_login.html")

var basicAuthLoginTemplate = template.Must(template.New("basicAuthLogin").Parse(basicAuthLoginPage))

// HiddenField is an OAuth2 parameter carried across the login form POST.
type HiddenField struct {
	Name  string
	Value string
}

// BasicAuthLoginData is what the login template renders.
type BasicAuthLoginData struct {
	Error  string
	Email  string
	Hidden []HiddenField
}

// BasicAuthLoginHandler renders the email/password login form.
func BasicAuthLoginHandler(data BasicAuthLoginData) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := basicAuthLoginTemplate.Execute(w, data); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})
}
