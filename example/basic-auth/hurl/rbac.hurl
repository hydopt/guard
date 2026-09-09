# Role-based access control: bob (role "user") may read /private but is
# rejected by /private/admin, which requires the "admin" role.
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
email: bob@example.com
password: password
HTTP 302
[Captures]
callback_url: header "Location"

GET {{callback_url}}
HTTP 302
[Asserts]
header "Location" == "/"

# Signed in as bob: /private works...
GET {{base_url}}/private
HTTP 200
[Asserts]
body contains "bob@example.com"

# ...but /private/admin is forbidden for non-admin roles.
GET {{base_url}}/private/admin
HTTP 403
[Asserts]
body contains "Forbidden"