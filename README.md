# idm-api

this api allows you to manage accounts within ldap instances.

# examples

## create account

    curl -X POST \
      --header "Content-Type: application/json" \
      --data '{"username":"foo", "surname":"whatever","password":"foo"}' https://example.org/account

## update password

    export USERNAME=foo

    curl -X POST \
      --header "Content-Type: application/json" \
      --data '{"old":"oldpw", "new": "newpw", "repeat":"newpw"}' \
      https://example.org/account/${USERNAME}/password
