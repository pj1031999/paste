package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	_ "github.com/lib/pq"
    "net/http"
)

// aes encrypted data 
type Message struct {
	Username string
	Password string
	Command string // action
	Content string // action parametr
	Name string // name if action is "add"
}

type RMessLS struct {
	Name []string
	Show []bool
}

var (
	CIPHER_KEY []byte
	HOST string
	DB string
	USER string
	PASSWORD string
	db *sql.DB
    CUSER string
    CPASSWD string
)

func Init() {
	// 32 or 16 bytes
	CIPHER_KEY = []byte(os.Getenv("PASTE_AES"))
    CUSER = os.Getenv("PASTE_USERNAME")
    CPASSWD = os.Getenv("PASTE_PASSWORD")
	HOST = os.Getenv("PASTE_HOST")
	DB = os.Getenv("PASTE_DB")
	USER = os.Getenv("PASTE_USER")
	PASSWORD = os.Getenv("PASTE_PASSWD")
	dbinfo := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable", HOST, USER, PASSWORD, DB)

	var err error
	db, err = sql.Open("postgres", dbinfo)
	if err != nil {
		panic(err)
	}
}

func httpserve() {
    h := http.NewServeMux()
    h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        response := get(r.URL.Path[1:])
        w.Header().Set("Content-Type", "text/plaintext")
        fmt.Fprintln(w, response)
    })
    err := http.ListenAndServe(":8080", h)
    log.Fatal(err)
}

func main() {
    log.Printf("%v: started\n", os.Args[0])
	Init()
	defer db.Close()

    go httpserve()

	server, err  := net.Listen("tcp", ":4977")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := server.Accept()
		defer conn.Close()

		if err != nil {
			panic(err)
		}

		tmp := make([]byte, 1024 * 1024 * 16)
		_, err = conn.Read(tmp)

		if err != nil {
			panic(err)
		}

		tmpbuff := bytes.NewBuffer(tmp)
		tmpstruct := new(Message)

		gobobj := gob.NewDecoder(tmpbuff)
		gobobj.Decode(tmpstruct)

		tmpstruct.Username, err = decrypt(CIPHER_KEY, tmpstruct.Username)
		tmpstruct.Password, err = decrypt(CIPHER_KEY, tmpstruct.Password)
		tmpstruct.Command, err = decrypt(CIPHER_KEY, tmpstruct.Command)
		tmpstruct.Content, err = decrypt(CIPHER_KEY, tmpstruct.Content)
		tmpstruct.Name, err = decrypt(CIPHER_KEY, tmpstruct.Name)

        if tmpstruct.Username != CUSER || tmpstruct.Password != CPASSWD {
            conn.Write([]byte("auth error"))
            continue
        }

		switch tmpstruct.Command {
		case "add":
			add_command(tmpstruct, conn)
		case "del":
			del_command(tmpstruct, conn)
		case "ls":
			ls_command(conn)
		case "pull":
			pull_command(tmpstruct, conn)
		case "show":
			show_command(tmpstruct, conn)
		case "hide":
			hide_command(tmpstruct, conn)
		default:
			conn.Write([]byte("Unknown command"))
		}
	}
}

func add_command(msg *Message, conn net.Conn) {
	log.Printf("add_command: %v", msg.Name)

	rows, err := db.Query("SELECT name FROM paste where name = $1", msg.Name)

	if err != nil {
		panic(err)
	}

	ok := true
	for rows.Next() {
		ok = false
		break
	}

	if ok == false {
		conn.Write([]byte("name exists"))
		return
	}

	_, err = db.Exec("INSERT INTO paste (name,content,show) VALUES ($1,$2,$3)", msg.Name, msg.Content, false)

	if err != nil {
		panic(err)
	}

	conn.Write([]byte("OK"))
}

func del_command(msg *Message, conn net.Conn) {
	log.Printf("show_command: %v", msg.Name)
	_, err := db.Exec("DELETE FROM paste where name=$1", msg.Name)
	if err != nil {
		conn.Write([]byte(err.Error()))
		return
	}
	conn.Write([]byte("OK"))
}

func ls_command(conn net.Conn) {
	log.Printf("ls_commnad")
	rows, err := db.Query("SELECT name, show FROM paste")

	if err != nil {
		panic(err)
	}

	result_name := make([]string, 0)
	result_show := make([]bool, 0)
	for rows.Next() {
		var rw string
		var show bool
		rows.Scan(&rw, &show)
		rw, err = encrypt(CIPHER_KEY, rw)
		if err != nil {
			panic(err)
		}
		result_name = append(result_name, rw)
		result_show = append(result_show, show)
	}

	var rmess RMessLS
	rmess.Name = result_name
	rmess.Show = result_show

	bin_buf := new(bytes.Buffer)
	gobobj := gob.NewEncoder(bin_buf)
	gobobj.Encode(rmess)
	conn.Write(bin_buf.Bytes())
}

func pull_command(msg *Message, conn net.Conn) {
	log.Printf("pull_command: %v", msg.Name)
	rows, err := db.Query("SELECT content FROM paste WHERE name=$1", msg.Name)

	if err != nil {
		conn.Write([]byte(err.Error()))
		return
	}

	for rows.Next() {
		var rw string
		rows.Scan(&rw)
		conn.Write([]byte(rw))
	}

	conn.Write([]byte("name not exists"))
}

func get(name string) string {
    log.Printf("get: %v", name)
	rows, err := db.Query("SELECT content,show FROM paste WHERE name=$1", name)

    if err != nil {
        return err.Error()
    }

    for rows.Next() {
        var rw string
        var show bool
        rows.Scan(&rw, &show)
        if show == true {
            return rw
        }
        return "None"
    }

    return "None"
}

func show_command(msg *Message, conn net.Conn) {
	log.Printf("show_command: %v", msg.Name)
	_, err := db.Exec("UPDATE PASTE SET show=true WHERE name=$1", msg.Name)
	if err != nil {
		conn.Write([]byte(err.Error()))
		return
	}
	conn.Write([]byte("OK"))
}


func hide_command(msg *Message, conn net.Conn) {
	log.Printf("hide_command: %v", msg.Name)
	_, err := db.Exec("UPDATE PASTE SET show=false WHERE name=$1", msg.Name)
	if err != nil {
		conn.Write([]byte(err.Error()))
		return
	}
	conn.Write([]byte("OK"))
}

func encrypt(key []byte, msg string) (string, error) {
	plainText := []byte(msg)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	encrypted := base64.StdEncoding.EncodeToString(cipherText)
	return encrypted, nil
}

func decrypt(key []byte, msg string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return "", err
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	decrypted := string(cipherText)
	return decrypted, nil
}
