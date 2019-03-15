package main

import (
  "encoding/json"
  "fmt"
  "log"
  "os"
  "net/http"
  "github.com/gorilla/mux"

  "metagit.org/fnordpipe/idm-api/modules/ldap"

  ini "gopkg.in/ini.v1"
)

var cfg *ini.File
var tree ldap.Tree

type JsonAccount struct {
  Username string `json:"username,omitempty"`
  Surname string `json:"surname,omitempty"`
  Password string `json:"password,omitempty"`
}

type JsonAccountResponse struct {
  Username bool `json:"username"`
  Password bool `json:"password"`
  Surname bool `json:"surname"`
}

func CreateAccount(w http.ResponseWriter, r *http.Request) {
  var account JsonAccount
  var ar = JsonAccountResponse{true, true, true}
  _ = json.NewDecoder(r.Body).Decode(&account)

  if account.Username == "" {
    ar.Username = false
  }

  if account.Password == "" {
    ar.Password = false
  }

  if account.Surname == "" {
    ar.Surname = false
  }

  if !ar.Username || !ar.Password || !ar.Surname {
    w.WriteHeader(http.StatusBadRequest)
    json.NewEncoder(w).Encode(ar)
    return
  }

  a, err := tree.SearchAccount(account.Username)
  if err != nil {
    a = ldap.Account{
      CommonName: account.Username,
      Surname: account.Surname,
      Username: account.Username,
      Password: account.Password,
    }
    err = tree.CreateAccount(a)
    if err != nil {
      w.WriteHeader(http.StatusInternalServerError)
      return
    } else {
      w.WriteHeader(http.StatusCreated)
      return
    }
  }

  ar.Username = false
  w.WriteHeader(http.StatusConflict)
  json.NewEncoder(w).Encode(ar)
}

func main() {
  if len(os.Args) != 2 {
    fmt.Fprintf(os.Stderr, "USAGE: %s <config>\n", os.Args[0])
    os.Exit(1)
  }
  var err error
  cfg, err = ini.Load(os.Args[1])
  if err != nil {
    fmt.Fprintf(os.Stderr, "Failed to read file %v\n", err)
    os.Exit(2)
  }

  host := cfg.Section("server").Key("listen").MustString("127.0.0.1")
  port := cfg.Section("server").Key("port").MustInt(5555)

  ls := &ldap.Source{
    Host: cfg.Section("ldap").Key("host").MustString("127.0.0.1"),
    Port: cfg.Section("ldap").Key("port").MustInt(389),
    BindDN: cfg.Section("ldap").Key("bind").String(),
    BindPassword: cfg.Section("ldap").Key("password").String(),
  }

  tree = ldap.Tree{
    Base: cfg.Section("ldap").Key("base").String(),
    AttributeCommonName: cfg.Section("ldap").Key("cn").MustString("cn"),
    AttributePassword: cfg.Section("ldap").Key("userpassword").MustString("userPassword"),
    AttributeSurname: cfg.Section("ldap").Key("sn").MustString("sn"),
    AttributeUsername: cfg.Section("ldap").Key("uid").MustString("uid"),
    Filter: cfg.Section("ldap").Key("filter").String(),
    Ls: ls,
  }

  router := mux.NewRouter()
  router.HandleFunc("/account", CreateAccount).Methods("POST")

  log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", host, port), router))
}
