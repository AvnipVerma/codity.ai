"""Names that sound secret, values that are not."""

token_url = "https://auth.example.com/oauth2/token"
password_reset_endpoint = "/account/password/reset"
SECRET_KEY_ENV_VAR = "APP_SECRET_KEY"
api_key_header = "X-Api-Key"
key_name = "api_key"
password_field = "user_password_input"
PASSWORD_HELP_TEXT = "Use at least 12 characters, including a digit and a symbol."
token_type = "Bearer"
password = "password"
DEFAULT_ADMIN_PASSWORD_LENGTH = "24"


def login_form_fields():
    return {"username_field": "email", "password_field": "passwd"}
