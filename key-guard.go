package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"github.com/atotto/clipboard"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

// key must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256)
func aesencrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// aes decrypt
func aesdecrypt(cipherTextBase64 string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Generate a random salt
func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}

// Hash the password using Argon2id and encode all parameters into one string
func hashPassword(password string) (string, error) {
	salt, err := generateSalt(16)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: salt$hash
	return fmt.Sprintf("%s$%s", encodedSalt, encodedHash), nil
}

// Verifies if input password matches the stored hash string
func verifyPassword(storedHash, inputPassword string) bool {
	parts := strings.Split(storedHash, "$")
	if len(parts) != 2 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	realHash, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	testHash := argon2.IDKey([]byte(inputPassword), salt, 1, 64*1024, 4, 32)
	return string(testHash) == string(realHash)
}

// cmd line options
// init -- set up a master password
// add -- add a username&password for a account
// get -- copy the passwd&username in clipboard for a account
// delete -- delete a account
// list -- list all accounts
// help -- help with usage

var helpMsg string = `
Welcome to Key-Guard Password Manager

Usage commands

help - Show the list of cmds available for usage
init - Initialises the master account with password
add [account-name] - Adds the given account name and prompts for username and password
get [account-name] - Copies the username and password for the given account name into clipboard
delete [account-name] - Deletes the given account
list - Lists all the acounts that has been added
`

func main() {
	fmt.Println(os.Args)
	argument := strings.ToLower(os.Args[1])
	switch argument {
	case "help":
		fmt.Println(helpMsg)
	case "init":
		db, err := sql.Open("sqlite3", "data.db")
		if err != nil {
			panic(err)
		}
		defer db.Close()
		createTable := `
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT,
            username TEXT,
            password TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hashed_passwd TEXT
        );`
		_, err = db.Exec(createTable)
		if err != nil {
			panic(err)
		}
		var passwd string
		row := db.QueryRow(`SELECT COUNT(*) FROM users`)

		var count int
		row.Scan(&count)
		if count > 0 {
			fmt.Println("⚠️ Master password is set already exists.")
			return
		}

		fmt.Println("Enter master password")
		fmt.Scanln(&passwd)
		hashed_passwd, _ := hashPassword(passwd)
		stmt, _ := db.Prepare("INSERT INTO users (hashed_passwd) VALUES ( ?)")
		_, _ = stmt.Exec(hashed_passwd)
		fmt.Println("✅ Account added.")

	case "add":
		if len(os.Args) == 3 {
			db, _ := sql.Open("sqlite3", "file:data.db?mode=rw")
			err := db.Ping()
			if err != nil {
				fmt.Println("❌ Database file does not exist or cannot be opened.")
				return
			}
			defer db.Close()
			usr_row := db.QueryRow(`SELECT COUNT(*) FROM users`)

			var ct int
			usr_row.Scan(&ct)
			if ct == 0 {
				fmt.Println("Master password is not set run key-guard init.")
				return
			}
			row := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE account = ?`, strings.ToLower(os.Args[2]))
			var count int
			row.Scan(&count)
			if count > 0 {
				var opt string
				fmt.Println("⚠️ This account already exists. Do you want to overwrite the credentials [y/n]")
				fmt.Scanln(&opt)
				if strings.ToLower(opt) == "y" {
					var oldHash, masterpwd string
					fmt.Println("Enter Master Password")
					fmt.Scanln(&masterpwd)
					stmt := db.QueryRow(`SELECT hashed_passwd from users`)
					stmt.Scan(&oldHash)
					if !verifyPassword(oldHash, masterpwd) {
						fmt.Println("Master Password does not match")
					}
					var username, password string
					fmt.Println("Enter username")
					fmt.Scanln(&username)
					fmt.Println("Enter password")
					fmt.Scanln(&password)
					row_update, _ := db.Prepare(`UPDATE accounts SET username = ?, password = ? WHERE account = ?`)

					encryptedpwd, err := aesencrypt(password, []byte(oldHash)[:16])
					if err != nil {
						fmt.Println("❌ Encryption failed:", err)
						return
					}
					row_update.Exec(username, encryptedpwd, os.Args[2])
					fmt.Println("Credentials Updated")
				}
				return
			}

			var oldHash, masterpwd string
			fmt.Println("Enter Master Password")
			fmt.Scanln(&masterpwd)
			stmt := db.QueryRow(`SELECT hashed_passwd from users`)
			stmt.Scan(&oldHash)
			if !verifyPassword(oldHash, masterpwd) {
				fmt.Println("Master Password does not match")
				return
			}
			var username, password string
			fmt.Println("Enter username")
			fmt.Scanln(&username)
			fmt.Println("Enter password")
			fmt.Scanln(&password)
			row_insert, _ := db.Prepare(`INSERT INTO accounts (account, username, password) VALUES (?, ?, ?)`)
			encryptedpwd, _ := aesencrypt(password, []byte(oldHash)[:16])
			row_insert.Exec(os.Args[2], username, encryptedpwd)
			fmt.Println("Credentials Added")
			return
		}
		fmt.Println("Invalid arguments provided Check help for more info")

	case "list":
		db, _ := sql.Open("sqlite3", "file:data.db?mode=ro")
		err := db.Ping()
		if err != nil {
			fmt.Println("❌ Database file does not exist or cannot be opened.")
			return
		}
		defer db.Close()
		rows, _ := db.Query(`SELECT account from accounts`)
		for rows.Next() {
			var account string
			err := rows.Scan(&account)
			if err != nil {
				fmt.Println("❌ Scan error:", err)
				continue
			}
			fmt.Println(account)
		}
	case "delete":
		if len(os.Args) == 3 {
			db, _ := sql.Open("sqlite3", "file:data.db?mode=rw")
			err := db.Ping()
			if err != nil {
				fmt.Println("❌ Database file does not exist or cannot be opened.")
				return
			}
			defer db.Close()
			var oldHash, masterpwd string
			fmt.Println("Enter Master Password")
			fmt.Scanln(&masterpwd)
			stmt := db.QueryRow(`SELECT hashed_passwd from users`)
			stmt.Scan(&oldHash)
			res := verifyPassword(oldHash, masterpwd)
			if !res {
				fmt.Println("Master Password does not match")
				return
			}
			del_stmt, _ := db.Prepare(`DELETE FROM accounts WHERE account = ?`)
			del_stmt.Exec(os.Args[2])
			fmt.Println("Deleted Successfully")
			return
		}
		fmt.Println("Invalid arguments provided Check help for more info")
	case "get":
		if len(os.Args) == 3 {
			db, _ := sql.Open("sqlite3", "file:data.db?mode=rw")
			err := db.Ping()
			if err != nil {
				fmt.Println("❌ Database file does not exist or cannot be opened.")
				return
			}
			defer db.Close()
			var oldHash, masterpwd string
			fmt.Println("Enter Master Password")
			fmt.Scanln(&masterpwd)
			stmt := db.QueryRow(`SELECT hashed_passwd from users`)
			stmt.Scan(&oldHash)
			res := verifyPassword(oldHash, masterpwd)
			if !res {
				fmt.Println("Master Password does not match")
				return
			}
			var account, username, passwd string
			sel_stmt := db.QueryRow(`SELECT account, username, password FROM accounts WHERE account = ?`,os.Args[2])
			err = sel_stmt.Scan(&account, &username, &passwd)
			if err != nil {
				if err == sql.ErrNoRows {
					fmt.Println("No record found")
				} else {
					log.Fatal("Scan error:", err)
				}
				return
			}
			passwdtext, errstr := aesdecrypt(passwd,[]byte(oldHash)[:16])
			if errstr != nil{
				fmt.Println(errstr)
				break
			}
			clipboardText := fmt.Sprintf(`%s\n\n%s`,username,passwdtext)
			err = clipboard.WriteAll(clipboardText)
			if err != nil {
				fmt.Println("Error copying to clipboard:", err)
				return
			}
			fmt.Println("Copied Successfully")
			return
		}
		fmt.Println("Invalid arguments provided Check help for more info")
	case "check":
		db, _ := sql.Open("sqlite3", "file:data.db?mode=ro")
		err := db.Ping()
		if err != nil {
			fmt.Println("❌ Database file does not exist or cannot be opened.")
			return
		}
		defer db.Close()
		var oldHash, masterpwd string
		fmt.Println("Enter Master Password")
		fmt.Scanln(&masterpwd)
		stmt := db.QueryRow(`SELECT hashed_passwd from users`)
		stmt.Scan(&oldHash)
		res := verifyPassword(oldHash, masterpwd)
		if !res {
			fmt.Println("Master Password does not match")
			return
		}
	}
}
