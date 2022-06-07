package basicauth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/mkawserm/abesh/iface"
	"github.com/mkawserm/abesh/model"

	"github.com/amjadjibon/authorizer/basiauth/constant"
)

type BasicAuth struct {
	mCM       model.ConfigMap
	mUsername string
	mPassword string
}

func (b *BasicAuth) GetConfigMap() model.ConfigMap {
	return b.mCM
}

func (b *BasicAuth) SetConfigMap(cm model.ConfigMap) error {
	b.mCM = cm
	b.mUsername = cm.String("username", "")
	b.mPassword = cm.String("password", "")

	if len(b.mUsername) == 0 || len(b.mPassword) == 0 {
		return errors.New("username or password can not be empty")
	}

	return nil
}

func (b *BasicAuth) Name() string {
	return Name
}

func (b *BasicAuth) Version() string {
	return constant.Version
}

func (b *BasicAuth) Category() string {
	return Category
}

func (b *BasicAuth) ContractId() string {
	return ContractId
}

func (b *BasicAuth) New() iface.ICapability {
	return &BasicAuth{}
}

func (b *BasicAuth) IsAuthorized(expression string, metadata *model.Metadata) bool {
	var authorization, found = getHeaderValueSafe(metadata, "Authorization")
	if !found {
		return false
	}
	if len(authorization) == 0 {
		return false
	}
	var username, password, ok = parseBasicAuth(authorization)
	if !ok || !equal(b.mUsername, username) || !equal(b.mPassword, password) {
		return false
	}

	return true
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case-insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !equalFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

// EqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func equalFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func getHeaderValueSafe(metadata *model.Metadata, header string) (headerData string, found bool) {
	headerData, found = metadata.Headers[header]
	if found {
		return headerData, found
	}
	headerData, found = metadata.Headers[strings.ToLower(header)]
	return headerData, found
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
