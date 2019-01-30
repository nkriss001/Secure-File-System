package proj2


// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"
	
	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// For the useful little debug printing function
	"fmt"
	"time"
	"os"
	"strings"

	// I/O
	"io"
	
	// Want to import errors
	"errors"
	
	// These are imported for the structure definitions.  You MUST
	// not actually call the functions however!!!
	// You should ONLY call the cryptographic functions in the
	// userlib, as for testing we may add monitoring functions.
	// IF you call functions in here directly, YOU WILL LOSE POINTS
	// EVEN IF YOUR CODE IS CORRECT!!!!!
	"crypto/rsa"
)


// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings(){
	// Creates a random UUID
	f := uuid.New()
	debugMsg("UUID as string:%v", f.String())
	
	// Example of writing over a byte of f
	f[0] = 10
	debugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	debugMsg("The hex: %v", h)
	
	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d,_ := json.Marshal(f)
	debugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	debugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	debugMsg("Creation of error %v", errors.New("This is an error"))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *rsa.PrivateKey
	key,_ = userlib.GenerateRSAKey()
	debugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range(ret){
		ret[x] = data[x]
	}
	return
}

// Helper function: Returns a byte slice of the specificed
// size filled with random data
func randomBytes(bytes int) (data []byte){
	data = make([]byte, bytes)
	if _, err := io.ReadFull(userlib.Reader, data); err != nil {
		panic(err)
	}
	return
}

var DebugPrint = false

// Helper function: Does formatted printing to stderr if
// the DebugPrint global is set.  All our testing ignores stderr,
// so feel free to use this for any sort of testing you want
func debugMsg(format string, args ...interface{}) {
	if DebugPrint{
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		fmt.Fprintf(os.Stderr,
			msg + strings.Trim(format, "\r\n ") + "\n", args...)
	}
}

// Helper function: Generate deterministic location of a user
// struct, and that user's encryption and hash keys
func userKeys(username []byte, password []byte) (eKey []byte, hKey []byte,
	lKey []byte) {
	key := userlib.PBKDF2Key(password, append([]byte("a"), username...), 80)
	eKey = key[:16]
	hKey = key[16:48]
	lKey = key[48:80]
	return
}

// Helper function: Encrypt data
func encrypt(eKey []byte, data []byte) (iv []byte, ciphertext []byte, err error) {
	iv = randomBytes(userlib.BlockSize)
	ciphertext = make([] byte, len(data))
	cipher := userlib.CFBEncrypter(eKey, iv)
	cipher.XORKeyStream(ciphertext, []byte(data))
	return iv, ciphertext, nil
}

// Helper function: Decrypt data
func decrypt(eKey []byte, iv []byte, ciphertext []byte) (plaintext []byte, err error) {
	plaintext = make([] byte, len(ciphertext))
	cipher := userlib.CFBDecrypter(eKey, iv)
	cipher.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// Helper function: Create HMAC of data
func createHMAC(hKey []byte, data []byte) (hmac []byte, err error) {
	mac := userlib.NewHMAC(hKey)
	mac.Write(data)
	hmac = mac.Sum(nil)
	return hmac, nil
}

// Helper function: Confirm HMAC of data
func confirmHMAC(hKey []byte, hmac []byte, data []byte) (err error) {
	mac := userlib.NewHMAC(hKey)
	mac.Write(data)
	t := mac.Sum(nil)
	if !userlib.Equal(t, hmac) {
		return errors.New("Data corrupted")
	}
	return nil
}

// Helper function: Encrypt, HMAC and store data in the datastore
func store(eKey []byte, hKey []byte, lKey []byte, data []byte) (err error) {
	iv, ciphertext, err := encrypt(eKey, data)
	if err != nil {
		return errors.New("Failed to encrypt data")
	}
	hmac,err := createHMAC(hKey, append(iv, ciphertext...))
	if err != nil {
		return errors.New("Failed to MAC data")
	}
	userlib.DatastoreSet(string(lKey), append(hmac, append(iv, ciphertext...)...))
	return nil

}

// Helper function: Decrypt, confirm HMAC and load data from the datastore
func load(eKey []byte, hKey []byte, lKey []byte) (data []byte, err error){
	hashsize := userlib.HashSize
	blocksize := userlib.BlockSize
	
	store,ok := userlib.DatastoreGet(string(lKey))
	if !ok {
		return nil, errors.New("Data does not exist")
	}

	if len(store) < hashsize + blocksize {
		return nil, errors.New("Data corrupted")
	}

	hmac := store[:hashsize]
	iv := store[hashsize:hashsize + blocksize]
	ciphertext := store[hashsize + blocksize:]

	err = confirmHMAC(hKey, hmac, append(iv, ciphertext...))
	if err != nil {
		return nil, errors.New("Failed to load data")
	}

	data,err = decrypt(eKey, iv, ciphertext)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	RSAKey *rsa.PrivateKey
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}



// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error){
	var userdata User
	userdata.Username = username
	userdata.Password = password
	rsaKey,_ := userlib.GenerateRSAKey()
	userdata.RSAKey = rsaKey
	userlib.KeystoreSet(username, rsaKey.PublicKey)
	
	eKey, hKey, lKey := userKeys([]byte(username), []byte(password))
	marshal,_ := json.Marshal(userdata)
	err = store(eKey, hKey, lKey, marshal)
	if err != nil {
		return nil, errors.New("Failed to initialize user")
	}
	return &userdata, err
}


// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error){
	var userdata User
	
	eKey, hKey, lKey := userKeys([]byte(username), []byte(password))
	
	plaintext,err := load(eKey, hKey, lKey)
	if err != nil {
		return nil, errors.New("Failed to retrieve user")
	}
	json.Unmarshal(plaintext, &userdata)
	if userdata.Username != username || userdata.Password != password {
		return nil, errors.New("Retrieved invalid user")
	}
	return &userdata, nil
}



// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	username := userdata.Username
	password := userdata.Password
	fileEKey := randomBytes(16)
	fileHKey := randomBytes(32)
	metaLKey := randomBytes(32)
	fileLKey := randomBytes(32)
	key := append(fileEKey, append(fileHKey, metaLKey...)...)
	
	userEKey, userHKey, _ := userKeys([]byte(username), []byte(password))
	userLKey,_ := createHMAC(userHKey, []byte(password + filename))
	
	store(userEKey, userHKey, userLKey, key)
	iv, ciphertext, _ := encrypt(fileEKey, data)
	hmac,_ := createHMAC(fileHKey, append(iv, ciphertext...))
	store(fileEKey, fileHKey, metaLKey, append(hmac, fileLKey...))
	userlib.DatastoreSet(string(fileLKey), append(iv, ciphertext...))
}


// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error){
	username := userdata.Username
	password := userdata.Password
	appendLKey := randomBytes(32)
	userEKey, userHKey, _ := userKeys([]byte(username), []byte(password))
	userLKey,_ := createHMAC(userHKey, []byte(password + filename))

	key, err := load(userEKey, userHKey, userLKey)
	if err != nil {
		return errors.New("Metadata corrupted")
	}

	fileEKey := key[:16]
	fileHKey := key[16:48]
	metaLKey := key[48:]

	metaKeys, err := load(fileEKey, fileHKey, metaLKey)
	if err != nil {
		return errors.New("Locations corrupted")
	}

	iv, ciphertext, _ := encrypt(fileEKey, data)
	prevHMAC := metaKeys[len(metaKeys) - 32 - userlib.HashSize:len(metaKeys) - 32]
	hmac,_ := createHMAC(fileHKey, append(iv, append(ciphertext, prevHMAC...)...))
	metaKeys = append(metaKeys, append(hmac, appendLKey...)...)
	err = store(fileEKey, fileHKey, metaLKey, metaKeys)
	if err != nil {
		return errors.New("Failed to append")
	}
	userlib.DatastoreSet(string(appendLKey), append(iv, ciphertext...))
	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string)(data []byte, err error) {
	blocksize := userlib.BlockSize
	hashsize := userlib.HashSize
	username := userdata.Username
	password := userdata.Password
	userEKey, userHKey, _ := userKeys([]byte(username), []byte(password))
	userLKey,_ := createHMAC(userHKey, []byte(password + filename))

	key,err := load(userEKey, userHKey, userLKey)
	if err != nil && err.Error() == "Data does not exist" {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("Metadata corrupted")
	}
	
	fileEKey := key[:16]
	fileHKey := key[16:48]
	metaLKey := key[48:80]
	data = nil

	metaKeys, err := load(fileEKey, fileHKey, metaLKey)
	if err != nil {
		return nil, errors.New("Locations corrupted")
	}
	prevHMAC := []byte(nil)

	for i := 0; i < len(metaKeys); i += 32 + hashsize {
		hmac := metaKeys[i:i+hashsize]
		appendLKey := metaKeys[i+hashsize:i+32+hashsize]
		file,ok := userlib.DatastoreGet(string(appendLKey))
		if !ok {
			return nil, errors.New("Failed to load file")
		}
		if len(file) < userlib.BlockSize {
			return nil, errors.New("Failed to load file")
		}
		iv := file[:blocksize]
		ciphertext := file[blocksize:]
		err = confirmHMAC(fileHKey, hmac, append(iv, append(ciphertext, prevHMAC...)...))
		if err != nil {
			return nil, errors.New("Failed to load file")
		}
		plaintext,_ := decrypt(fileEKey, iv, ciphertext)
		data = append(data, plaintext...)
		prevHMAC = hmac
	}

	return data, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}


// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string)(
	msgid string, err error){
	username := userdata.Username
	password := userdata.Password
	userEKey, userHKey, _ := userKeys([]byte(username), []byte(password))
	userLKey,_ := createHMAC(userHKey, []byte(password + filename))

	key,err := load(userEKey, userHKey, userLKey)
	if err != nil {
		return "", errors.New("Metadata corrupted")
	}

	seedKey := randomBytes(32)
	tempKeys := userlib.PBKDF2Key(seedKey, nil, 80)
	tempEKey := tempKeys[:16]
	tempHKey := tempKeys[16:48]
	tempLKey := tempKeys[48:80]

	private := userdata.RSAKey
	public,exist := userlib.KeystoreGet(recipient)
	if !exist {
		return "", errors.New("Recipient does not exist")
	}
	send,sendErr := userlib.RSAEncrypt(&public, seedKey, nil)
	if sendErr != nil {
		return "", errors.New("Failed to encrypt message")
	}
	sig,sigErr := userlib.RSASign(private, send)
	if sigErr != nil {
		return "", errors.New("Failed to sign message")
	}

	err = store(tempEKey, tempHKey, tempLKey, append(sig, key...))
	return string(send), nil
}


// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	username := userdata.Username
	password := userdata.Password
	private := userdata.RSAKey
	public,exist := userlib.KeystoreGet(sender)
	if !exist {
		return errors.New("Sender does not exist")
	}

	seedKey,err := userlib.RSADecrypt(private, []byte(msgid), nil)
	if err != nil {
		return errors.New("Failed to decrypt message")
	}
	tempKeys := userlib.PBKDF2Key(seedKey, nil, 80)
	tempEKey := tempKeys[:16]
	tempHKey := tempKeys[16:48]
	tempLKey := tempKeys[48:80]

	plaintext,err := load(tempEKey, tempHKey, tempLKey)
	if err != nil {
		return errors.New("Failed to share file")
	}
	if len(plaintext) < 256 {
		return errors.New("Failed to retrieve filedata")
	}

	sig := plaintext[:256]
	key := plaintext[256:]
	err = userlib.RSAVerify(&public, []byte(msgid), sig)
	if err != nil {
		return errors.New("Message ID corrupted")
	}

	userEKey, userHKey, _ := userKeys([]byte(username), []byte(password))
	userLKey,_ := createHMAC(userHKey, []byte(password + filename))

	err = store(userEKey, userHKey, userLKey, key)
	if err != nil {
		return errors.New("Failed to share file")
	}
	return nil
}

// Removes access for all others.  
func (userdata *User) RevokeFile(filename string) (err error){
	blocksize := userlib.BlockSize
	hashsize := userlib.HashSize
	username := userdata.Username
	password := userdata.Password
	userEKey, userHKey, _ := userKeys([]byte(username), []byte(password))
	userLKey,_ := createHMAC(userHKey, []byte(password + filename))

	key,err := load(userEKey, userHKey, userLKey)
	if err != nil {
		return errors.New("Metadata corrupted")
	}
	
	fileEKey := key[:16]
	fileHKey := key[16:48]
	metaLKey := key[48:80]
	data := []byte(nil)

	metaKeys, err := load(fileEKey, fileHKey, metaLKey)
	if err != nil {
		return errors.New("Locations corrupted")
	}
	prevHMAC := []byte(nil)

	for i := 0; i < len(metaKeys); i += 32 + hashsize {
		hmac := metaKeys[i:i+hashsize]
		appendLKey := metaKeys[i+hashsize:i+32+hashsize]
		file,ok := userlib.DatastoreGet(string(appendLKey))
		if !ok {
			return errors.New("Failed to load file")
		}
		if len(file) < userlib.BlockSize {
			return errors.New("Failed to load file")
		}
		iv := file[:blocksize]
		ciphertext := file[blocksize:]
		err = confirmHMAC(fileHKey, hmac, append(iv, append(ciphertext, prevHMAC...)...))
		if err != nil {
			return errors.New("Failed to load file")
		}
		plaintext,_ := decrypt(fileEKey, iv, ciphertext)
		data = append(data, plaintext...)
		prevHMAC = hmac
		userlib.DatastoreSet(string(appendLKey), nil)
	}
	userlib.DatastoreSet(string(metaKeys), nil)

	fileEKey = randomBytes(16)
	fileHKey = randomBytes(32)
	metaLKey = randomBytes(32)
	fileLKey := randomBytes(32)
	key = append(fileEKey, append(fileHKey, metaLKey...)...)
	
	store(userEKey, userHKey, userLKey, key)
	iv, ciphertext, _ := encrypt(fileEKey, data)
	hmac,_ := createHMAC(fileHKey, append(iv, ciphertext...))
	store(fileEKey, fileHKey, metaLKey, append(hmac, fileLKey...))
	userlib.DatastoreSet(string(fileLKey), append(iv, ciphertext...))

	return nil
}
