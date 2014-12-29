build:
	go run gen.go
	openssl x509 -in server.crt -inform DER -out server.pem
	openssl x509 -in client.crt -inform DER -out client.pem
	openssl rsa -in client.key -inform DER -out client.key
	openssl rsa -in server.key -inform DER -out server.key
	chmod 600 *.key *.pem *.crt
	@echo
	@echo "------------------------------------------------------------"
	@echo "    only .crt, .pem and .key files have been built          "
	@echo "------------------------------------------------------------"

clean:
	rm -f *.crt *.pem *.key
