package ldap

import (
  "fmt"
  "os"

  ldap "gopkg.in/ldap.v3"

  "math/rand"
  "github.com/GehirnInc/crypt"
  _ "github.com/GehirnInc/crypt/sha512_crypt"
)

type Account struct {
  CommonName string
  Surname string
  Username string
  Password string
}

type Source struct {
  Host string
  Port int
  BindDN string
  BindPassword string
}

type Tree struct {
  Base string
  AttributeCommonName string
  AttributePassword string
  AttributeSurname string
  AttributeUsername string
  Filter string
  Ls *Source
}

func connect(ls *Source, dn, password string) (*ldap.Conn, error) {
  fmt.Fprintf(os.Stdout, "Connecting to LDAP server %s:%d\n", ls.Host, ls.Port)
  c, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ls.Host, ls.Port))
  if err != nil {
    return nil, err
  }

  err = c.Bind(dn, password)
  return c, err
}

func createSalt(n int) string {
  const characters = "abcdefghijklmnopqrstvuwxyzABCDEFGHIJKLMNOPQRSTVUWXYZ0123456789./"
  l := len(characters)
  b := make([]byte, n)
  for i := range b {
    b[i] = characters[rand.Int63() % int64(l)]
  }
  return string(b)
}

func createPassword(password string) string {
  crypt := crypt.SHA512.New()
  hash, _ := crypt.Generate([]byte(password), []byte(fmt.Sprintf("$6$%s", createSalt(16))))
  return fmt.Sprintf("{CRYPT}%s", hash)
}

func (t *Tree) ChangePassword(username, password, old string) error {
  dn := fmt.Sprintf("%s=%s,%s", t.AttributeUsername, username, t.Base)
  l, err := connect(t.Ls, dn, old)
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    return err
  }
  defer l.Close()

  mr := ldap.NewModifyRequest(dn, nil)
  mr.Replace(t.AttributePassword, []string{createPassword(password)})

  fmt.Fprintf(os.Stdout, "Changing Password for %s\n", username)
  err = l.Modify(mr)
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    return err
  }

  return nil
}

func (t *Tree) CreateAccount(account Account) error {
  l, err := connect(t.Ls, t.Ls.BindDN, t.Ls.BindPassword)
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    return err
  }
  defer l.Close()

  dn := fmt.Sprintf("%s=%s,%s", t.AttributeUsername, account.Username, t.Base)
  ar := ldap.NewAddRequest(dn, nil)
  ar.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "top"})
  ar.Attribute(t.AttributeCommonName, []string{account.CommonName})
  ar.Attribute(t.AttributeSurname, []string{account.Surname})
  ar.Attribute(t.AttributeUsername, []string{account.Username})
  ar.Attribute(t.AttributePassword, []string{createPassword(account.Password)})

  fmt.Fprintf(os.Stdout, "Creating account %s in %s\n", account.Username, t.Base)
  err = l.Add(ar)
  if err != nil {
    return err
  }

  return nil
}

func (t *Tree) SearchAccount(username string) (Account, error) {
  var account Account

  l, err := connect(t.Ls, t.Ls.BindDN, t.Ls.BindPassword)
  if err != nil {
    fmt.Fprintf(os.Stderr, "%v\n", err)
    return account, err
  }
  defer l.Close()

  filter := fmt.Sprintf("(&%s(%s=%s))",
    t.Filter, t.AttributeUsername, username)
  sr := ldap.NewSearchRequest(
    t.Base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
    0, 0, false, filter,
    []string{}, nil)

  fmt.Fprintf(os.Stdout, "Searching for account %s in %s\n", username, t.Base)
  s, err := l.Search(sr)
  if err != nil {
    return account, err
  }

  if len(s.Entries) != 1 || s.Entries[0].DN == "" {
    return account, fmt.Errorf("Cannot find account %s in %s", username, t.Base)
  }

  account = Account{
    CommonName: s.Entries[0].GetAttributeValue(t.AttributeCommonName),
    Password: s.Entries[0].GetAttributeValue(t.AttributePassword),
    Surname: s.Entries[0].GetAttributeValue(t.AttributeSurname),
    Username: s.Entries[0].GetAttributeValue(t.AttributeUsername),
  }

  return account, nil
}
