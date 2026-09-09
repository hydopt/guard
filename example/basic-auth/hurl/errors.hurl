# Wrong credentials re-render the login form with an error and no session.
GET {{base_url}}/auth/basic-auth
HTTP 302
[Captures]
authorize_url: header "Location"

GET {{authorize_url}}
HTTP 200
[Captures]
state: regex "<input type=\"hidden\" name=\"state\" value=\"([^\"]*)\">"
nonce: regex "<input type=\"hidden\" name=\"nonce\" value=\"([^\"]*)\">"
challenge: regex "<input type=\"hidden\" name=\"code_challenge\" value=\"([^\"]*)\">"
redirect_uri: regex "<input type=\"hidden\" name=\"redirect_uri\" value=\"([^\"]*)\">"

POST {{authorize_url}}
[FormParams]
redirect_uri: {{redirect_uri}}
state: {{state}}
nonce: {{nonce}}
code_challenge: {{challenge}}
email: alice@example.com
password: wrong-password
HTTP 200
[Asserts]
body contains "Invalid email or password"

# Without a session, the protected routes still redirect to the sign-in page.
GET {{base_url}}/private
HTTP 302
[Asserts]
header "Location" contains "/signin"