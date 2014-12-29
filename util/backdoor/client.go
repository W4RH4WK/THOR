package main

import (
	"crypto/tls"
	"io"
	"log"
	"os"
)

func main() {
	clientpem := []byte(`-----BEGIN CERTIFICATE-----
MIICLjCCAZmgAwIBAgICBnowCwYJKoZIhvcNAQELMDQxEDAOBgNVBAYTB0F1c3Ry
aWExETAPBgNVBAoTCEhlYXBsb2NrMQ0wCwYDVQQLEwRUSE9SMB4XDTE0MTIyOTIw
MjgxNloXDTI0MTIyOTIwMjgxNlowNDEQMA4GA1UEBhMHQXVzdHJpYTERMA8GA1UE
ChMISGVhcGxvY2sxDTALBgNVBAsTBFRIT1IwgZ8wDQYJKoZIhvcNAQEBBQADgY0A
MIGJAoGBALU8nHHU80Npw36kBX2e8yM+wzWcqu4kCnOctyM7IQy13rA1LIm62gEU
ApH5tl2JtgTISgFevnLgScVgg+jMqVQliQ5wlHF5XL9fdYCpYw547cN+dOMosPfa
RYkFs0HNoMmgkFCRkSmN9YMu0I1C19GVrUFKo6gPK2CA/9F6v/3PAgMBAAGjUzBR
MA4GA1UdDwEB/wQEAwIAhDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
DgYDVR0OBAcEBQECAwQGMBAGA1UdIwQJMAeABQECAwQFMAsGCSqGSIb3DQEBCwOB
gQC3DNFu25IIxJyK5CwkYDjab/yXh7oCBzwyRTwobCvXBH5VYR01VmurRImADN8a
MKleoXSBRryjikEuLaILUwYCFwPcKatGTv7sF4ofYSEB4sdUtLcxmfu68ZZxVqD5
e5iNBHU/sFQmM87qUh4MX4wFxd/7x0pWv0t2jbNvv18KiQ==
-----END CERTIFICATE-----`)

	clientkey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC1PJxx1PNDacN+pAV9nvMjPsM1nKruJApznLcjOyEMtd6wNSyJ
utoBFAKR+bZdibYEyEoBXr5y4EnFYIPozKlUJYkOcJRxeVy/X3WAqWMOeO3DfnTj
KLD32kWJBbNBzaDJoJBQkZEpjfWDLtCNQtfRla1BSqOoDytggP/Rer/9zwIDAQAB
AoGBAJ1Pd+eiVGh+Q+8HhbCNKDO+hYhibUd5Rw0kyR2udDhpIFrIPNlrs1BeQwDb
w/wazUAHbZ0U1LA3mDDXXofSJWJqBklyzDfbvJ0zELtWjmgeQy4SSYPAxFgOPAgA
fqPj5kGSoxTfPPjtb1l1/nOV7dq4S0ip/hDjyDxPj1YrSJdRAkEA7HuVSREkifJd
n+uzVhIOR0hoqnA7wlgNbGp+h6hebi/7qcNX6vVvTWUEogh3SrbnjOG0aFbHfnv+
7dcWJG4R5wJBAMQxyeKOYb/U6K2IagU298sYl7lo45qITyzGuuN3swqlKwIm6YKl
pT4xB5+NgdgrfvnSlHqw4Qr6+hYxECWuh9kCQQDjajU1/vZUcm72y4O60cJJaqi8
vxG441SFXiQv8QpejGZH60MxALX4h5zc9adCgoJKSQNlE47lY/jUYHM6tV8hAkAx
uLCCYzUwqaOiPv0nfyvDY+Mn0QZFpp/yKBc7CJ3uZ7eDnxr0ykgbf89/xxwODc/r
Pkv04BjYcIyqzRpbgmTZAkAcEC9QV6iaYpYoJCBa/SVW/+dnA41Qo7khlXQubIXt
yvrgDMN3ejbHTaqmnPRPLSp1ljA+cglj0xuOacmckv3S
-----END RSA PRIVATE KEY-----`)

	crt, err := tls.X509KeyPair(clientpem, clientkey)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("certificate loaded")

	cfg := tls.Config{
		Certificates:       []tls.Certificate{crt},
		InsecureSkipVerify: true,
	}

	con, err := tls.Dial("tcp", "localhost:1337", &cfg)
	if err != nil {
		log.Fatalln("Error:", err.Error())
	}

	go io.Copy(os.Stdout, con)
	go io.Copy(os.Stderr, con)
	io.Copy(con, os.Stdin)

	con.Close()
}
