package compare

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/kataras/jwt"
	"github.com/pavel-v-chernykh/keystore-go/v4"
	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/compare", new(Compare))
}

type Compare struct{}

var mySigningKey byte

const saltLen = 20

var supportedPrivateKeyAlgorithmOid = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1})
var (
	ErrEntryNotFound           = errors.New("entry not found")
	ErrWrongEntryType          = errors.New("wrong entry type")
	ErrEmptyPrivateKey         = errors.New("empty private key")
	ErrEmptyCertificateType    = errors.New("empty certificate type")
	ErrEmptyCertificateContent = errors.New("empty certificate content")
	ErrShortPassword           = errors.New("short password")
)

type keyInfo struct {
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type KeyStore struct {
	m map[string]interface{}
	r io.Reader

	ordered        bool
	caseExact      bool
	minPasswordLen int
}

// PrivateKeyEntry is an entry for private keys and associated certificates.
type PrivateKeyEntry struct {
	encryptedPrivateKey []byte

	CreationTime     time.Time
	PrivateKey       []byte
	CertificateChain []Certificate
}

// TrustedCertificateEntry is an entry for certificates only.
type TrustedCertificateEntry struct {
	CreationTime time.Time
	Certificate  Certificate
}

// Certificate describes type of certificate.
type Certificate struct {
	Type    string
	Content []byte
}

type Option func(store *KeyStore)

// For testing create the RSA key pair in the code
func readKeyStore(filename string, password []byte) keystore.KeyStore {

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	ks := keystore.New()
	if err := ks.Load(f, password); err != nil {
		log.Fatal(err) // nolint: gocritic
	}

	return ks
}
func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}
func (ks KeyStore) GetPrivateKeyEntry(alias string, password []byte) (PrivateKeyEntry, error) {
	e, ok := ks.m[ks.convertAlias(alias)]
	if !ok {
		return PrivateKeyEntry{}, ErrEntryNotFound
	}

	pke, ok := e.(PrivateKeyEntry)
	if !ok {
		return PrivateKeyEntry{}, ErrWrongEntryType
	}

	dpk, err := decrypt(pke.encryptedPrivateKey, password)
	if err != nil {
		return PrivateKeyEntry{}, fmt.Errorf("decrypt private key: %w", err)
	}

	pke.encryptedPrivateKey = nil
	pke.PrivateKey = dpk

	return pke, nil
}

func passwordBytes(password []byte) []byte {
	result := make([]byte, 0, len(password)*2)
	for _, b := range password {
		result = append(result, 0, b)
	}

	return result
}

func decrypt(data []byte, password []byte) ([]byte, error) {
	var keyInfo keyInfo

	asn1Rest, err := asn1.Unmarshal(data, &keyInfo)
	if err != nil {
		return nil, fmt.Errorf("unmarshal encrypted key: %w", err)
	}

	if len(asn1Rest) > 0 {
		return nil, errors.New("got extra data in encrypted key")
	}

	if !keyInfo.Algo.Algorithm.Equal(supportedPrivateKeyAlgorithmOid) {
		return nil, errors.New("got unsupported private key encryption algorithm")
	}

	md := sha1.New()

	passwordBytes := passwordBytes(password)
	defer zeroing(passwordBytes)

	salt := make([]byte, saltLen)
	copy(salt, keyInfo.PrivateKey)
	encryptedKeyLen := len(keyInfo.PrivateKey) - saltLen - md.Size()
	numRounds := encryptedKeyLen / md.Size()

	if encryptedKeyLen%md.Size() != 0 {
		numRounds++
	}

	encryptedKey := make([]byte, encryptedKeyLen)
	copy(encryptedKey, keyInfo.PrivateKey[saltLen:])

	xorKey := make([]byte, encryptedKeyLen)

	digest := salt

	for i, xorOffset := 0, 0; i < numRounds; i++ {
		if _, err := md.Write(passwordBytes); err != nil {
			return nil, fmt.Errorf("update digest with password on %d round: %w", i, err)
		}

		if _, err := md.Write(digest); err != nil {
			return nil, fmt.Errorf("update digest with digest from previous round on %d round: %w", i, err)
		}

		digest = md.Sum(nil)
		md.Reset()
		copy(xorKey[xorOffset:], digest)
		xorOffset += md.Size()
	}

	plainKey := make([]byte, encryptedKeyLen)
	for i := 0; i < len(plainKey); i++ {
		plainKey[i] = encryptedKey[i] ^ xorKey[i]
	}

	if _, err := md.Write(passwordBytes); err != nil {
		return nil, fmt.Errorf("update digest with password: %w", err)
	}

	if _, err := md.Write(plainKey); err != nil {
		return nil, fmt.Errorf("update digest with plain key: %w", err)
	}

	digest = md.Sum(nil)
	md.Reset()

	digestOffset := saltLen + encryptedKeyLen
	if !bytes.Equal(digest, keyInfo.PrivateKey[digestOffset:digestOffset+len(digest)]) {
		return nil, errors.New("got invalid digest")
	}

	return plainKey, nil
}

func (ks KeyStore) convertAlias(alias string) string {
	if ks.caseExact {
		return alias
	}

	return strings.ToLower(alias)
}

type Header struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

func (*Compare) IsGreater() string {

	password := []byte{'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'}
	defer zeroing(password)
	ks := readKeyStore("keystore.jks", password)
	//	fmt.Printf("%v", ks1)

	pke, err := ks.GetPrivateKeyEntry("buypass", password)
	//	fmt.Println("$$$$$$$$$$$$$$$$$$$$:>>>>>>>>>>>>>>>>>>>>>>>", pke)

	if err != nil {
		log.Fatal(err) // nolint: gocritic
	}

	mySigningKey, err := x509.ParsePKCS8PrivateKey(pke.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	header := Header{
		Kid: "2839535039619243700807470",
		Alg: jwt.RS256.Name(),
	}
	//	log.Printf("%#v", mySigningKey)
	// Generate a token:
	myClaims := map[string]interface{}{
		"scope": "idporten:dcr.read",
		"exp":   time.Now().Unix() + 120,
		"aud":   "https://maskinporten-systest.dev.eid.digdirnfl.no/",
		"iss":   "oidc_test_jwt_go",
		"iat":   time.Now().Unix(),
	}

	jwtsign, err := jwt.SignWithHeader(jwt.RS256, mySigningKey, myClaims, header, jwt.MaxAge(2*time.Minute))
	jwtassertion := string(jwtsign)

	//fmt.Printf("err: %v\n", jwtassertion)

	return jwtassertion
}
