# Full email/password sign-in flow: unauthenticated redirect to the sign-in
# page, provider start, login form render, credential exchange, minted session
# token, and protected access with the session cookie.
GET {{base_url}}/private
HTTP 302
[Asserts]
header "Location" == "/signin?next=%2Fprivate"

# Start the basic-auth provider: redirects to the local authorize endpoint.
GET {{base_url}}/auth/basic-auth
HTTP 302
[Captures]
authorize_url: header "Location"
[Asserts]
header "Location" contains "/auth/basic-auth/authorize"

# Render the login form and capture the OAuth2 state carried as hidden fields.
GET {{authorize_url}}
HTTP 200
[Captures]
state: regex "<input type=\"hidden\" name=\"state\" value=\"([^\"]*)\">"
nonce: regex "<input type=\"hidden\" name=\"nonce\" value=\"([^\"]*)\">"
challenge: regex "<input type=\"hidden\" name=\"code_challenge\" value=\"([^\"]*)\">"
redirect_uri: regex "<input type=\"hidden\" name=\"redirect_uri\" value=\"([^\"]*)\">"
[Asserts]
body contains "Enter your email and password"

# Submit credentials; the server answers with an authorization code.
POST {{authorize_url}}
[FormParams]
client_id: basic-auth
response_type: code
redirect_uri: {{redirect_uri}}
scope: openid email
state: {{state}}
nonce: {{nonce}}
code_challenge: {{challenge}}
code_challenge_method: S256
email: alice@example.com
password: password
HTTP 302
[Captures]
callback_url: header "Location"
[Asserts]
header "Location" contains "/auth/basic-auth/callback"

# Exchange the code: the server mints the session token and sets the cookie.
GET {{callback_url}}
HTTP 302
[Asserts]
header "Location" == "/"
header "Set-Cookie" exists

# The session cookie now authenticates protected routes.
GET {{base_url}}/private
HTTP 200
[Asserts]
body contains "alice@example.com"
body contains "admin"