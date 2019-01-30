package proj2

import (
	"testing"
	"github.com/nweaver/cs161-p2/userlib"
	"bytes"
)
// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	DebugPrint = true
	//someUsefulThings()

	DebugPrint = true
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails 
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	if (*u).Username != "alice" || (*u).Password != "fubar" {
		t.Error("Failed to initialize user", err)
	}
	_,ok := userlib.KeystoreGet("alice")
	if !ok {
		t.Error("Failed to initialize user")
	}
	// You probably want many more tests here.
	u, err = InitUser("bob", "12AhLoi0")
	if err != nil {
		t.Error("Failed to initialize user", err)
	}
	t.Log("Got user", u)
	if (*u).Username != "bob" || (*u).Password != "12AhLoi0" {
		t.Error("Failed to initialize user", err)
	}
	_,ok = userlib.KeystoreGet("bob")
	if !ok {
		t.Error("Failed to initialize user")
	}

	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestGet(t *testing.T) {
	u,err := GetUser("alice", "password")
	if err == nil || u != nil {
		t.Error("User does not exist", err)
	}
	u,_ = InitUser("alice", "fubar")
	v, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
	}
	if (*u).Username != (*v).Username {
		t.Error("Failed to get user", err)
	}
	if (*u).Password != (*v).Password {
		t.Error("Failed to get user", err)
	}
	v, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
	}
	if (*u).Username != (*v).Username {
		t.Error("Failed to get user", err)
	}
	if (*u).Password != (*v).Password {
		t.Error("Failed to get user", err)
	}
	InitUser("alice", "password")
	u,err = GetUser("alice", "Password")
	if err == nil || u != nil {
		t.Error("User does not exist", err)
	}
	u,err = GetUser("olice", "password")
	if err == nil || u != nil {
		t.Error("User does not exist", err)
	}
	u,err = GetUser("alic", "epassword")
	if err == nil || u != nil {
		t.Error("User does not exist", err)
	}
	u,err = GetUser("alice", "password")
	if err != nil {
		t.Error("Failed to get user", err)
	}
	if (*u).Username != "alice" || (*u).Password != "password" {
		t.Error("Failed to get user", err)
	}

	v,_ = InitUser("bob", "fubar")
	u,err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
	}
	if (*u).Username != "alice" || (*u).Password != "fubar" {
		t.Error("Failed to get user", err)
	}
	v,err = GetUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
	}
	if (*u).Username != "alice" || (*u).Password != "fubar" {
		t.Error("Failed to get user", err)
	}
	if (*v).Username != "bob" || (*v).Password != "fubar" {
		t.Error("Failed to get user", err)
	}
	w,_ := InitUser("alice", "bob")
	u,err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
	}
	if (*u).Username != "alice" || (*u).Password != "fubar" {
		t.Error("Failed to get user", err)
	}
	w,err = GetUser("alice", "bob")
	if err != nil {
		t.Error("Failed to get user", err)
	}
	if (*w).Username != "alice" || (*w).Password != "bob" {
		t.Error("Failed to get user", err)
	}

	dataMap := userlib.DatastoreGetMap()
	_,ok := dataMap["alice"]
	if ok {
		t.Error("Fail to protect username")
	}
	eKey, hKey, lKey := userKeys([]byte("nick"), []byte("kriss"))
	dataMap[string(lKey)] = []byte("PWNED")
	u,err = GetUser("nick", "kriss")
	if err == nil {
		t.Error("Failed to detect error")
	}
	store(eKey, hKey, lKey, []byte("PWNED"))
	u,err = GetUser("nick", "kriss")
	if err == nil {
		t.Error("Failed to detect error")
	}

	eKey, hKey, lKey = userKeys([]byte("alice"), []byte("password"))
	badAlice,_ := dataMap[string(lKey)]
	userlib.DatastoreDelete(string(lKey))
	u,err = GetUser("alice", "password")
	if err == nil || u != nil {
		t.Error("Failed to detect error", err)
	}

	dataMap[string(lKey)] = nil
	u,err = GetUser("alice", "password")
	if err == nil || u != nil {
		t.Error("Failed to detect error", err)
	}

	badAlice[0] += 1
	dataMap[string(lKey)] = badAlice
	u,err = GetUser("alice", "password")
	if err == nil || u != nil {
		t.Error("Failed to detect error", err)
	}
	badAlice[0] -= 1
	badAlice[len(badAlice) - 1] += 1
	dataMap[string(lKey)] = badAlice
	u,err = GetUser("alice", "password")
	if err == nil || u != nil {
		t.Error("Failed to detect error", err)
	}
	dataMap[string(lKey)] = []byte("adsoandGADSGAj	i403thgardn;dataMapheg")
	u,err = GetUser("alice", "password")
	if err == nil || u != nil {
		t.Error("Failed to detect error", err)
	}
	badAlice[len(badAlice) - 1] -= 1
	dataMap[string(lKey)] = badAlice
	u,err = GetUser("alice", "password")
	if err != nil {
		t.Error("Failed to get user", err)
	}
	if (*u).Username != "alice" || (*u).Password != "password" {
		t.Error("Failed to get user", err)
	}
}

func TestFiles(t *testing.T) {
	u,_ := GetUser("alice", "fubar")
	data := []byte("Hello World")
	u.StoreFile("data", data)
	u.StoreFile("hello", data)
	store,err := u.LoadFile("data")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}
	store,err = u.LoadFile("hello")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}
	store,err = u.LoadFile("hello")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}

	v,_ := GetUser("alice", "password")
	store,err = v.LoadFile("hello")
	if err != nil || store != nil {
		t.Error("Failed to detect nonexistant file", err)
	}
	v.StoreFile("hello", append(data, data...))
	store,err = v.LoadFile("hello")
	if err != nil || !bytes.Equal(append(data, data...), store) {
		t.Error("Failed to load file", err)
	}
	store,err = u.LoadFile("hello")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}
	store,err = u.LoadFile("hello")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}

	store,err = u.LoadFile("String")
	if err != nil || store != nil {
		t.Error("File does not exist", err)
	}
	store,err = v.LoadFile("datag")
	if err != nil || store != nil {
		t.Error("File does not exist", err)
	}

	userEKey, userHKey, _ := userKeys([]byte("alice"), []byte("fubar"))
	userLKey,_ := createHMAC(userHKey, []byte("fubar" + "data"))
	userlib.DatastoreDelete(string(userLKey))
	store,err = u.LoadFile("data")
	if err != nil || store != nil {
		t.Error("Failed to load file", err)
	}
	u.StoreFile("data", data)
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}
	userlib.DatastoreSet(string(userLKey), data)
	store,err = u.LoadFile("data")
	if err == nil || store != nil {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("data", data)
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}
	fileKeys,_ := userlib.DatastoreGet(string(userLKey))
	fileKeys[0] += 1 
	userlib.DatastoreSet(string(userLKey), fileKeys)
	store,err = u.LoadFile("data")
	if err == nil || store != nil {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("data", data)
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}

	key, err := load(userEKey, userHKey, userLKey)
	//fileEKey := key[:16]
	//fileHKey := key[16:48]
	metaLKey := key[48:]

	userlib.DatastoreDelete(string(metaLKey))
	store,err = u.LoadFile("data")
	if err == nil || store != nil {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("data", data)
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}
	key, err = load(userEKey, userHKey, userLKey)
	metaLKey = key[48:]
	userlib.DatastoreSet(string(metaLKey), data)
	store,err = u.LoadFile("data")
	if err == nil || store != nil {
		t.Error("Failed to detect error", store)
	}
	u.StoreFile("data", data)
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}
	key, err = load(userEKey, userHKey, userLKey)
	metaLKey = key[48:]
	metaKeys,_ := userlib.DatastoreGet(string(metaLKey))
	metaKeys[0] += 1 
	userlib.DatastoreSet(string(metaLKey), metaKeys)
	store,err = u.LoadFile("data")
	if err == nil || store != nil {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("data", data)
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data, store) {
		t.Error("Failed to load file", err)
	}

	userlib.DatastoreClear()
	userlib.KeystoreClear()
	u,_ = InitUser("alice", "fubar")
	u.StoreFile("string", []byte("string"))
	store,_ = u.LoadFile("string")
	if string(store) != "string" {
		t.Error("Failed to store file", err)
	}
	u.StoreFile("string", []byte("newstring"))
	store,_ = u.LoadFile("string")
	if string(store) != "newstring" {
		t.Error("Failed to store file", err)
	}
}

func TestAppend(t *testing.T) {
	u,_ := InitUser("alice", "fubar")
	data1 := []byte("Hello World")
	data2 := []byte("Goodbye World")
	data3 := append(data1, data2...)

	u.StoreFile("data", data1)
	err := u.AppendFile("data", data2)
	if err != nil {
		t.Error("Failed to append file", err)
	}
	store,err := u.LoadFile("data")
	if err != nil || !bytes.Equal(data3, store) {
		t.Error("Failed to load file", err)
	}
	data3 = append(data3, store...)
	err = u.AppendFile("data", store)
	if err != nil {
		t.Error("Failed to append file", err)
	}
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data3, store) {
		t.Error("Failed to load file", err)
	}

	data3 = append(data1, data2...)
	userEKey, userHKey, _ := userKeys([]byte("alice"), []byte("fubar"))
	userLKey,_ := createHMAC(userHKey, []byte("fubar" + "data"))
	userlib.DatastoreDelete(string(userLKey))
	err = u.AppendFile("data", data1)
	if err == nil {
		t.Error("Failed to detect error", err)
	}
	data := []byte("BAD")
	u.StoreFile("data", data)
	userlib.DatastoreSet(string(userLKey), []byte("WRONG"))
	err = u.AppendFile("data", data)
	if err == nil {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("data", data1)
	err = u.AppendFile("data", data2)
	if err != nil {
		t.Error("Failed to append file", err)
	}
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data3, store) {
		t.Error("Failed to load file", err)
	}
	fileKeys,_ := userlib.DatastoreGet(string(userLKey))
	fileKeys[0] += 1 
	userlib.DatastoreSet(string(userLKey), fileKeys)
	err = u.AppendFile("data", data)
	if err == nil {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("data", data1)
	err = u.AppendFile("data", data2)
	if err != nil {
		t.Error("Failed to append file", err)
	}
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data3, store) {
		t.Error("Failed to load file", err)
	}

	key, err := load(userEKey, userHKey, userLKey)
	//fileEKey := key[:16]
	//fileHKey := key[16:48]
	metaLKey := key[48:]

	userlib.DatastoreDelete(string(metaLKey))
	err = u.AppendFile("data", data)
	if err == nil {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("data", data1)
	err = u.AppendFile("data", data2)
	if err != nil {
		t.Error("Failed to append file", err)
	}
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data3, store) {
		t.Error("Failed to load file", err)
	}
	key, err = load(userEKey, userHKey, userLKey)
	metaLKey = key[48:]
	userlib.DatastoreSet(string(metaLKey), data)
	err = u.AppendFile("data", data)
	if err == nil {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("data", data1)
	err = u.AppendFile("data", data2)
	if err != nil {
		t.Error("Failed to append file", err)
	}
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data3, store) {
		t.Error("Failed to load file", err)
	}
	key, err = load(userEKey, userHKey, userLKey)
	metaLKey = key[48:]
	metaKeys,_ := userlib.DatastoreGet(string(metaLKey))
	metaKeys[0] += 1 
	userlib.DatastoreSet(string(metaLKey), metaKeys)
	err = u.AppendFile("data", data)
	if err == nil {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("data", data1)
	err = u.AppendFile("data", data2)
	if err != nil {
		t.Error("Failed to append file", err)
	}
	store,err = u.LoadFile("data")
	if err != nil || !bytes.Equal(data3, store) {
		t.Error("Failed to load file", err)
	}
}

func TestShare(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()

	alice,_ := InitUser("alice", "password")
	bob,_ := InitUser("bob", "Password")
	cat := []byte("Cat")
	dog := []byte("Dog")
	catdog := []byte("CatDog")

	alice.StoreFile("cat", cat)
	data,_ := alice.LoadFile("cat")
	data,err := bob.LoadFile("cat")
	if err != nil || data != nil {
		t.Error("Failed to load file", err)
	}

	msgid,err := alice.ShareFile("cat", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
	}
	err = bob.ReceiveFile("dog", "alice", msgid)
	if err != nil {
		t.Error("Failed to share file", err)
	}

	data,err = alice.LoadFile("cat")
	if err != nil || !bytes.Equal(cat, data) {
		t.Error("Failed to load file", err)
	}
	data,err = bob.LoadFile("cat")
	if err != nil || data != nil {
		t.Error("Failed to load file", err)
	}
	data,err = bob.LoadFile("dog")
	if err != nil || !bytes.Equal(cat, data) {
		t.Error("Failed to share file", err)
	}

	bob.AppendFile("dog", dog)
	data,err = bob.LoadFile("dog")
	if err != nil || !bytes.Equal(catdog, data) {
		t.Error("Failed to share file", err)
	}
	data,err = alice.LoadFile("cat")
	if err != nil || !bytes.Equal(catdog, data) {
		t.Error("Failed to share file", err)
	}

	alice.AppendFile("cat", catdog)
	data,err = bob.LoadFile("dog")
	if err != nil || !bytes.Equal(append(catdog, catdog...), data) {
		t.Error("Failed to share file", err)
	}
	data,err = alice.LoadFile("cat")
	if err != nil || !bytes.Equal(append(catdog, catdog...), data) {
		t.Error("Failed to share file", err)
	}

	alice.StoreFile("dog", dog)
	data,err = alice.LoadFile("dog")
	if err != nil || !bytes.Equal(dog, data) {
		t.Error("Failed to load file", err)
	}
	data,err = bob.LoadFile("dog")
	if err != nil || !bytes.Equal(append(catdog, catdog...), data) {
		t.Error("Failed to load file", err)
	}
	alice.StoreFile("newcat", cat)
	data,err = bob.LoadFile("newcat")
	if err != nil || data != nil {
		t.Error("Failed to share files", err)
	}

	alice.StoreFile("cat", dog)
	data,err = alice.LoadFile("cat")
	if err != nil || !bytes.Equal(dog, data) {
		t.Error("Failed to load file", err)
	}
	data,err = bob.LoadFile("dog")
	if err != nil || !bytes.Equal(append(catdog, catdog...), data) {
		t.Error("Failed to detect error", err)
	}

	msgid,err = alice.ShareFile("cat", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
	}
	err = bob.ReceiveFile("dog", "alice", msgid)
	if err != nil {
		t.Error("Failed to share file", err)
	}
	err = alice.RevokeFile("cat")
	if err != nil {
		t.Error("Failed to revoke file", err)
	}
	data,err = alice.LoadFile("cat")
	if err != nil || !bytes.Equal(dog, data) {
		t.Error("Failed to revoke file", err)
	}
	data,err = bob.LoadFile("dog")
	if err == nil || data != nil {
		t.Error("Failed to revoke file", err)
	}

	userlib.DatastoreClear()
	userlib.KeystoreClear()
	alice,_ = InitUser("alice", "fubar")
	bob,_ = InitUser("bob", "bar")
	mallory,_ := InitUser("mallory", "password")
	alice.StoreFile("test", []byte("test"))
	mallory.StoreFile("test", []byte("test"))
	msgid1,_ := alice.ShareFile("test", "bob")
	msgid2,_ := mallory.ShareFile("test", "bob")
	err = bob.ReceiveFile("file", "alice", msgid2)
	if err == nil {
		t.Error("Failed to detect wrong user", err)
	}
	err = bob.ReceiveFile("file", "alice", msgid1)
	if err != nil {
		t.Error("Failed to detect correct user", err)
	}
	err = bob.ReceiveFile("data", "alice", "msgid")
	if err == nil {
		t.Error("Failed to detect wrong user", err)
	}
	msgid,err = bob.ShareFile("file", "mallory")
	if err != nil {
		t.Error("Failed to share file", err)
	}
	data,err = mallory.LoadFile("share")
	if data != nil || err != nil {
		t.Error("Failed to detect missing file", err)
	}
	err = mallory.ReceiveFile("share", "bob", msgid)
	if err != nil {
		t.Error("Failed to share file", err)
	}
	data,err = mallory.LoadFile("share")
	if err != nil || !bytes.Equal(data, []byte("test")) {
		t.Error("Failed to share file", err)
	}
	err = mallory.AppendFile("share", []byte("test"))
	if err != nil {
		t.Error("Failed to share file", err)
	}
	data,err = mallory.LoadFile("share")
	if err != nil || !bytes.Equal(data, []byte("testtest")){
		t.Error("Failed to share file", err)
	}
	data,err = bob.LoadFile("file")
	if err != nil || !bytes.Equal(data, []byte("testtest")) {
		t.Error("Failed to share file", err)
	}
	data,err = alice.LoadFile("test")
	if err != nil || !bytes.Equal(data, []byte("testtest")) {
		t.Error("Failed to share file", err)
	}

	err = alice.RevokeFile("test")
	if err != nil {
		t.Error("Failed to revoke file", err)
	}
	data,err = bob.LoadFile("file")
	if err == nil || data != nil {
		t.Error("Failed to revoke file", err)
	}
	data,err = mallory.LoadFile("share")
	if err == nil || data != nil {
		t.Error("Failed to revoke file", err)
	}
	err = bob.ReceiveFile("file", "alice", msgid)
	if err == nil {
		t.Error("Failed to revoke file", err)
	}

	alice.StoreFile("test", []byte("test"))
	msgid,_ = alice.ShareFile("test", "mallory")
	err = mallory.ReceiveFile("share", "alice", msgid)
	if err != nil {
		t.Error("Failed to detect correct user", err)
	}
	data,err = mallory.LoadFile("share")
	if err != nil || !bytes.Equal(data, []byte("test")){
		t.Error("Failed to share file", err)
	}
	data,err = bob.LoadFile("file")
	if err == nil || data != nil {
		t.Error("Failed to revoke file", err)
	}

	msgid,_ = alice.ShareFile("test", "bob")
	malKey,_ := userlib.KeystoreGet("mallory")
	userlib.KeystoreSet("alice", malKey)
	err = bob.ReceiveFile("file", "alice", msgid)
	if err == nil {
		t.Error("Failed to detect error", err)
	}

	userlib.DatastoreClear()
	userlib.KeystoreClear()
	u,_ := InitUser("alice", "fubar")
	InitUser("bob", "password")
	u.StoreFile("alice", []byte("alice"))
	_, userHKey, _ := userKeys([]byte("alice"), []byte("fubar"))
	userLKey,_ := createHMAC(userHKey, []byte("fubar" + "alice"))
	userlib.DatastoreDelete(string(userLKey))
	msgid,err = u.ShareFile("alice", "bob")
	if err == nil || msgid != "" {
		t.Error("Failed to detect error", err)
	}
	userlib.DatastoreSet(string(userLKey), []byte("WRONG"))
	msgid,err = u.ShareFile("alice", "bob")
	if err == nil || msgid != "" {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("alice", []byte("alice"))
	msgid,err = u.ShareFile("alice", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
	}
	fileKeys,_ := userlib.DatastoreGet(string(userLKey))
	fileKeys[0] += 1 
	userlib.DatastoreSet(string(userLKey), fileKeys)
	msgid,err = u.ShareFile("alice", "bob")
	if err == nil || msgid != "" {
		t.Error("Failed to detect error", err)
	}
	u.StoreFile("alice", []byte("alice"))
	msgid,err = u.ShareFile("alice", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
	}
}

// Tests for when files/users do not exist
func TestNonexistent(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	u,err := GetUser("alice", "password")
	if err == nil || u != nil {
		t.Error("User does not exist", err)
	}
	u,_ = InitUser("alice", "password")
	u,err = GetUser("alice", "Password")
	if err == nil || u != nil {
		t.Error("User does not exist", err)
	}
	u,err = GetUser("olice", "password")
	if err == nil || u != nil {
		t.Error("User does not exist", err)
	}
	u,err = GetUser("alic", "epassword")
	if err == nil || u != nil {
		t.Error("User does not exist", err)
	}

	u,_ = GetUser("alice", "password")
	v,_ := InitUser("bob", "password")
	data := []byte("data")
	err = u.AppendFile("string", nil)
	if err == nil {
		t.Error("File does not exist", err)
	}
	err = v.AppendFile("string", data)
	if err == nil {
		t.Error("User does not exist", err)
	}
	u.StoreFile("string", data)
	err = u.AppendFile("String", data)
	if err == nil {
		t.Error("File does not exist", err)
	}
	err = v.AppendFile("string", data)
	if err == nil {
		t.Error("File does not exist", err)
	}

	msgid,err := u.ShareFile("string", "charles")
	if err == nil || msgid != "" {
		t.Error("User does not exist", err)
	}
	msgid,err = u.ShareFile("data", "bob")
	if err == nil || msgid != "" {
		t.Error("File does not exist", err)
	}
	msgid,err = u.ShareFile("string", "bob")
	if err != nil || msgid == "" {
		t.Error("User does not exist", err)
	}

	err = v.ReceiveFile("string", "alic", msgid)
	if err == nil {
		t.Error("User does not exist", err)
	}

	err = u.RevokeFile("strin")
	if err == nil {
		t.Error("File does not exist", err)
	}
}

func TestTwo(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	alice, _ := InitUser("alice", "fubar")
	also_alice, _ := GetUser("alice", "fubar")

	alice.StoreFile("todo", []byte("write tests"))
	todo, _ := also_alice.LoadFile("todo")
	if string(todo) != "write tests" {
		t.Error("Same user and password could not access file: ", todo)
	}

	alice.AppendFile("todo", []byte("write more tests"))
	todo, _ = also_alice.LoadFile("todo")
	if string(todo) != "write testswrite more tests" {
		t.Error("Same user and password could not access file: ", todo)
	}

	bob, _ := InitUser("bob", "password")
	bob.StoreFile("bob", []byte("bob"))
	msgid,_ := bob.ShareFile("bob", "alice")
	alice.ReceiveFile("alice", "bob", msgid)
	todo, _ = also_alice.LoadFile("alice")
	if string(todo) != "bob" {
		t.Error("Same user and password could not access file: ", todo)
	}

	bob.AppendFile("bob", []byte(" alice"))
	todo, _ = also_alice.LoadFile("alice")
	if string(todo) != "bob alice" {
		t.Error("Same user and password could not access file: ", todo)
	}

	bob.RevokeFile("bob")
	todo, err := also_alice.LoadFile("alice")
	if err == nil || todo != nil {
		t.Error("Failed to revoke file", err)
	}

	msgid,_ = alice.ShareFile("todo", "bob")
	bob.ReceiveFile("todo", "alice", msgid)
	bob.AppendFile("todo", []byte("TESTS"))
	todo, _ = also_alice.LoadFile("todo")
	if string(todo) != "write testswrite more testsTESTS" {
		t.Error("Same user and password could not access file: ", todo)
	}

	alice.RevokeFile("todo")
	todo, _ = also_alice.LoadFile("todo")
	if string(todo) != "write testswrite more testsTESTS" {
		t.Error("Same user and password could not access file: ", todo)
	}

	data,err := bob.LoadFile("todo")
	if data != nil || err == nil {
		t.Error("Failed to revoke file", err)
	}	
}

func TestExtra(t *testing.T) {
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	alice,_ := InitUser("alice", "password")
	bob,_ := InitUser("bob", "password")
}
