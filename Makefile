all: idm-api

idm-api:
	go get github.com/gorilla/mux
	go get gopkg.in/ldap.v3
	go get github.com/GehirnInc/crypt
	go get gopkg.in/ini.v1 
	go build

clean:
	rm idm-api
