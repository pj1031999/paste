package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"text/tabwriter"
)

var (
	CIPHER_KEY []byte
	HOST string
	USERNAME string
	PASSWORD string
)

// aes encrypted data 
type Message struct {
	Username string
	Password string
	Command string
	Content string
	Name string
}

type RMessLS struct {
	Name []string
	Show []bool
}

func Init() {
	// 16 or 32 bytes
	CIPHER_KEY = []byte(os.Getenv("PASTE_AES"))
	HOST = string(os.Getenv("PASTE_HOST"))
	USERNAME = string(os.Getenv("PASTE_USERNAME"))
	PASSWORD = string(os.Getenv("PASTE_PASSWORD"))


	if len(CIPHER_KEY) != 32 && len(CIPHER_KEY) != 16 {
		panic("PASTE_AES should have 16 or 32 byes")
	}
}

func main() {
	Init()

	command := os.Args[1]

	switch command {
	case "add":
		add_command()
	case "del":
		del_command()
	case "ls":
		ls_command()
	case "pull":
		pull_command()
	case "show":
		show_command()
	case "hide":
		hide_command()
	default:
		panic("Unknow command")
	}
}

func add_command() {
	name := os.Args[2]
	path := os.Args[3]

	paste_bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	msg := encrypted_msg("add", string(paste_bytes), name)

	conn, err := net.Dial("tcp", HOST + ":4977")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	bin_buf := new(bytes.Buffer)
	gobobj := gob.NewEncoder(bin_buf)
	gobobj.Encode(msg)
	conn.Write(bin_buf.Bytes())

	temp := make([]byte, 256)
	conn.Read(temp)
	log.Printf(string(temp))
}

func del_command() {
	name := os.Args[2]
	msg := encrypted_msg("del", name, name)

	conn, err := net.Dial("tcp", HOST + ":4977")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	bin_buf := new(bytes.Buffer)
	gobobj := gob.NewEncoder(bin_buf)
	gobobj.Encode(msg)
	conn.Write(bin_buf.Bytes())

	temp := make([]byte, 256)
	conn.Read(temp)
	log.Printf(string(temp))
}

func ls_command() {
	msg := encrypted_msg("ls", "", "")

	conn, err := net.Dial("tcp", HOST + ":4977")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	bin_buf := new(bytes.Buffer)
	gobobj := gob.NewEncoder(bin_buf)
	gobobj.Encode(msg)
	conn.Write(bin_buf.Bytes())


	tmp := make([]byte, 1024 * 1024 * 16)
	_, err = conn.Read(tmp)

	if err != nil {
		panic(err)
	}

	tmpbuff := bytes.NewBuffer(tmp)
	tmpstruct := new(RMessLS)

	gobobjD := gob.NewDecoder(tmpbuff)
	gobobjD.Decode(tmpstruct)


	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)


	fmt.Fprintln(w, "NAME\t|    SHOW")
	fmt.Fprintln(w, "================\t|===========")
	for it, name := range tmpstruct.Name {
		dec, err := decrypt(CIPHER_KEY, string(name))
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(w, fmt.Sprintf("%v\t|    %v", dec, tmpstruct.Show[it]))
		}
	w.Flush()
}

func pull_command() {
	name := os.Args[2]
	msg := encrypted_msg("pull", name, name)

	conn, err := net.Dial("tcp", HOST + ":4977")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	bin_buf := new(bytes.Buffer)
	gobobj := gob.NewEncoder(bin_buf)
	gobobj.Encode(msg)
	conn.Write(bin_buf.Bytes())

	temp := make([]byte, 1024 * 1024 * 16)
	conn.Read(temp)
	fmt.Printf(string(temp))
}

func show_command() {
	name := os.Args[2]
	msg := encrypted_msg("show", name, name)

	conn, err := net.Dial("tcp", HOST + ":4977")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	bin_buf := new(bytes.Buffer)
	gobobj := gob.NewEncoder(bin_buf)
	gobobj.Encode(msg)
	conn.Write(bin_buf.Bytes())

	temp := make([]byte, 256)
	conn.Read(temp)
	log.Printf(string(temp))
}

func hide_command() {
	name := os.Args[2]
	msg := encrypted_msg("hide", name, name)

	conn, err := net.Dial("tcp", HOST + ":4977")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	bin_buf := new(bytes.Buffer)
	gobobj := gob.NewEncoder(bin_buf)
	gobobj.Encode(msg)
	conn.Write(bin_buf.Bytes())

	temp := make([]byte, 256)
	conn.Read(temp)
	log.Printf(string(temp))
}


func encrypted_msg(cmd, content, name string) Message {
	var msg Message
	var err error

	msg.Content, err = encrypt(CIPHER_KEY, content)
	if err != nil {
		panic(err)
	}

	msg.Username, err = encrypt(CIPHER_KEY, USERNAME)
	if err != nil {
		panic(err)
	}

	msg.Password, err = encrypt(CIPHER_KEY, PASSWORD)
	if err != nil {
		panic(err)
	}

	msg.Command, err = encrypt(CIPHER_KEY, cmd)
	if err != nil {
		panic(err)
	}

	msg.Name, err = encrypt(CIPHER_KEY, name)
	if err != nil {
		panic(err)
	}

	return msg
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
