# ez_remoteshell
TLS remote shell server & client
- server & client verify each other's certificate

## Environment
- Ubuntu 18.04

## Build
```
sudo apt-get install libssl-dev
git clone https://github.com/LJP-TW/ez_remoteshell.git
cd ez_remoteshell
make
```

## Test
![](https://i.imgur.com/Jpi5Q3E.gif)

```
make runserver
```
```
make runclient
```
```
make runfakeclient
```

## Usage
### Server
```
./bin/ez_rsserver -i [ipv4] -p [port] -f [config]
```
for example:
```
./bin/ez_rsserver -i 0.0.0.0 -p 5566 -f config/server_config
```

### Client
```
./bin/ez_rsclient -i [ipv4] -p [port] -f [config]
```
for example:
```
./bin/ez_rsclient -i 127.0.0.1 -p 5566 -f config/client_config
```

### Config File

| Key | Description | Example |
| -------- | -------- | -------- |
| CA_CERT  | \[S\]\[C\] Path of CA certificate. | CA_CERT=./keys/CA-cert.pem |
| SERVER_CERT | \[S\] Path of server certificate | SERVER_CERT=./keys/server-cert.pem |
| SERVER_PKEY | \[S\] Path of server private key | SERVER_PKEY=./keys/server-key.pem |
| CLIENT_CERT | \[C\] Path of client certificate | CLIENT_CERT=./keys/client-cert.pem |
| CLIENT_PKEY | \[C\] Path of client private key | CLIENT_PKEY=./keys/client-key.pem

- \[S\] : Must set this key for server
- \[C\] : Must set this key for client
