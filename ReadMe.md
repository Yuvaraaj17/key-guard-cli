Key Guard v1.0 - Simple CLI tool to manage passwords (using GoLang)

Key Features
- 
1. Initialises a master user with a master password
2. Can able to add, delete account username and password
3. List all the added accounts
4. Copy required account username and password
5. Help command for usage help

Additional Usages

Used Argon2 hashing algorithm for Master Password
Used AES encryption & decryption algorithms for protecting account passwords
Utilizes a simple .db file as data store

Usage guide

cmd line options

key-guard init -- set up a master password \
key-guard add [account-name] -- add a username&password for a account \
key-guard get [account-name] -- copy the passwd&username in clipboard for a account \
key-guard delete [account-name] -- delete a account \
key-guard list -- list all accounts \
key-guard help -- help with usage 

Build with

CGO_ENABLED=1 -- env variable \
go build -tags "sqlite_omit_load_extension" -o ./bin/

There is prebuilt binary provided in the bin folder you can play around and check that.
