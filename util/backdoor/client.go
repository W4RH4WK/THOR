package main

import (
	"io"
	"log"
	"net"
	"os"
)

func main() {
	con, err := net.Dial("tcp", "localhost:1337")
	if err != nil {
		log.Fatalln("Error:", err.Error())
	}

	go io.Copy(os.Stdout, con)
	go io.Copy(os.Stderr, con)
	io.Copy(con, os.Stdin)

	con.Close()
}
