CreateCA:
	echo 'generate CA key...'
	openssl genrsa -aes-256-cbc -out CA-key.pem 2048
	echo 'generate CA certificate...'
	openssl req -new -key CA-key.pem -x509 -days 1000 -out CA-cert.pem

CreateCA2:
	echo 'generate CA key...'
	openssl genrsa -aes-256-cbc -out CA2-key.pem 2048
	echo 'generate CA certificate...'
	openssl req -new -key CA2-key.pem -x509 -days 1000 -out CA2-cert.pem

CreateServerKeypair:
	openssl genrsa -aes-256-cbc -out server-key.pem 2048

GenerateServerCSR:
	openssl req -new -key server-key.pem -out server-cert.csr

SignServerCSR:
	openssl x509 -req -days 360 -in server-cert.csr -CA CA-cert.pem -CAkey CA-key.pem -CAcreateserial -out server-cert.pem -sha256

CreateClientKeypair:
	openssl genrsa -aes-256-cbc -out client-key.pem 2048

GenerateClientCSR:
	openssl req -new -key client-key.pem -out client-cert.csr

SignClientCSR:
	openssl x509 -req -days 360 -in client-cert.csr -CA CA-cert.pem -CAkey CA-key.pem -CAcreateserial -out client-cert.pem -sha256

CreateFakeClientKeypair:
	openssl genrsa -aes-256-cbc -out fakeclient-key.pem 2048

GenerateFakeClientCSR:
	openssl req -new -key fakeclient-key.pem -out fakeclient-cert.csr

SignFakeClientCSR:
	openssl x509 -req -days 360 -in fakeclient-cert.csr -CA CA2-cert.pem -CAkey CA2-key.pem -CAcreateserial -out fakeclient-cert.pem -sha256

clear:
	rm ./*.pem
	rm ./*.csr
	rm ./*.srl
