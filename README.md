# Authentication service

Service for jwt authentication. Can authenticate users with JWT payload. Use refresh and access tokens to create new pair of tokens. Able to revoke already issued refresh tokens and unauthorize users with strange activity revoking all their refresh tokens.

# Config file example
To start a service you need to use config file.
Example of default config file
```yaml
env: "local" 

http_server:
  address: ":8888"

storage:
  postgres:
    url: "postgres://user:1234@localhost:5433/db"
    max_conns: 10
    min_conns: 3

auth:
  secret_key: "your-very-secure-secret-key-at-least-32-chars"
  access_expire_period_minutes: 15  
  refresh_token_expire_period_minutes: 1440 
  refresh_token_cookie_name: "medods_app_refresh_token"
```