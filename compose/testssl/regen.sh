rm -- *.key *.crt *.csr
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout localhost.key -out localhost.crt -subj "/CN=murfffi" -addext "subjectAltName=DNS:localhost"

#with CA cart:
#openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout ca.key -out ca.crt -subj "/CN=murfffi"
#openssl req -new -newkey rsa:4096 -sha256 -nodes -keyout localhost.key -out localhost.csr -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
#openssl x509 -req -in localhost.csr -CA ca.crt -CAkey ca.key \
# -CAcreateserial -out localhost.crt -days 825 -sha256 -extfile localhost.ext
