#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/test_certs"

echo "=== Certificate Generation Script ==="
echo "Output directory: ${CERT_DIR}"
echo ""

rm -rf "${CERT_DIR}"
mkdir -p "${CERT_DIR}"

mkdir -p "${CERT_DIR}/traditional/rsa"
mkdir -p "${CERT_DIR}/traditional/ecdsa"
mkdir -p "${CERT_DIR}/chain"
mkdir -p "${CERT_DIR}/selfsigned"
mkdir -p "${CERT_DIR}/expired"
mkdir -p "${CERT_DIR}/san-types"
mkdir -p "${CERT_DIR}/client"
mkdir -p "${CERT_DIR}/wildcard"
mkdir -p "${CERT_DIR}/p12-format"
mkdir -p "${CERT_DIR}/with-text"

echo "[1/7] Generating RSA certificates..."
cd "${CERT_DIR}/traditional/rsa"

openssl genrsa -out ca-rsa2048.key 2048
openssl req -new -x509 -days 365 -key ca-rsa2048.key -out ca-rsa2048.crt \
    -subj "/CN=Test RSA CA 2048/O=Test/C=IT"

openssl genrsa -out server-rsa2048.key 2048
openssl req -new -key server-rsa2048.key -out server-rsa2048.csr \
    -subj "/CN=localhost/O=TestServer/C=IT"
openssl x509 -req -days 365 -in server-rsa2048.csr \
    -CA ca-rsa2048.crt -CAkey ca-rsa2048.key -CAcreateserial -out server-rsa2048.crt
rm -f *.csr *.srl

openssl genrsa -out ca-rsa3072.key 3072
openssl req -new -x509 -days 365 -key ca-rsa3072.key -out ca-rsa3072.crt \
    -subj "/CN=Test RSA CA 3072/O=Test/C=IT"

openssl genrsa -out server-rsa3072.key 3072
openssl req -new -key server-rsa3072.key -out server-rsa3072.csr \
    -subj "/CN=localhost/O=TestServer/C=IT"
openssl x509 -req -days 365 -in server-rsa3072.csr \
    -CA ca-rsa3072.crt -CAkey ca-rsa3072.key -CAcreateserial -out server-rsa3072.crt
rm -f *.csr *.srl

openssl genrsa -out ca-rsa4096.key 4096
openssl req -new -x509 -days 365 -key ca-rsa4096.key -out ca-rsa4096.crt \
    -subj "/CN=Test RSA CA 4096/O=Test/C=IT"

openssl genrsa -out server-rsa4096.key 4096
openssl req -new -key server-rsa4096.key -out server-rsa4096.csr \
    -subj "/CN=localhost/O=TestServer/C=IT"
openssl x509 -req -days 365 -in server-rsa4096.csr \
    -CA ca-rsa4096.crt -CAkey ca-rsa4096.key -CAcreateserial -out server-rsa4096.crt
rm -f *.csr *.srl

echo "[2/6] Generating ECDSA certificates..."
cd "${CERT_DIR}/traditional/ecdsa"

openssl ecparam -name prime256v1 -genkey -out ca-ecdsa-p256.key
openssl req -new -x509 -days 365 -key ca-ecdsa-p256.key -out ca-ecdsa-p256.crt \
    -subj "/CN=Test ECDSA P-256 CA/O=Test/C=IT"

openssl ecparam -name prime256v1 -genkey -out server-ecdsa-p256.key
openssl req -new -key server-ecdsa-p256.key -out server-ecdsa-p256.csr \
    -subj "/CN=localhost/O=TestServer/C=IT"
openssl x509 -req -days 365 -in server-ecdsa-p256.csr \
    -CA ca-ecdsa-p256.crt -CAkey ca-ecdsa-p256.key -CAcreateserial -out server-ecdsa-p256.crt
rm -f *.csr *.srl

openssl ecparam -name secp384r1 -genkey -out ca-ecdsa-p384.key
openssl req -new -x509 -days 365 -key ca-ecdsa-p384.key -out ca-ecdsa-p384.crt \
    -subj "/CN=Test ECDSA P-384 CA/O=Test/C=IT"

openssl ecparam -name secp384r1 -genkey -out server-ecdsa-p384.key
openssl req -new -key server-ecdsa-p384.key -out server-ecdsa-p384.csr \
    -subj "/CN=localhost/O=TestServer/C=IT"
openssl x509 -req -days 365 -in server-ecdsa-p384.csr \
    -CA ca-ecdsa-p384.crt -CAkey ca-ecdsa-p384.key -CAcreateserial -out server-ecdsa-p384.crt
rm -f *.csr *.srl

openssl ecparam -name secp521r1 -genkey -out ca-ecdsa-p521.key
openssl req -new -x509 -days 365 -key ca-ecdsa-p521.key -out ca-ecdsa-p521.crt \
    -subj "/CN=Test ECDSA P-521 CA/O=Test/C=IT"

openssl ecparam -name secp521r1 -genkey -out server-ecdsa-p521.key
openssl req -new -key server-ecdsa-p521.key -out server-ecdsa-p521.csr \
    -subj "/CN=localhost/O=TestServer/C=IT"
openssl x509 -req -days 365 -in server-ecdsa-p521.csr \
    -CA ca-ecdsa-p521.crt -CAkey ca-ecdsa-p521.key -CAcreateserial -out server-ecdsa-p521.crt
rm -f *.csr *.srl

openssl genpkey -algorithm ED25519 -out ca-ed25519.key
openssl req -new -x509 -days 365 -key ca-ed25519.key -out ca-ed25519.crt \
    -subj "/CN=Test Ed25519 CA/O=Test/C=IT"

openssl genpkey -algorithm ED25519 -out server-ed25519.key
openssl req -new -key server-ed25519.key -out server-ed25519.csr \
    -subj "/CN=localhost/O=TestServer/C=IT"
openssl x509 -req -days 365 -in server-ed25519.csr \
    -CA ca-ed25519.crt -CAkey ca-ed25519.key -CAcreateserial -out server-ed25519.crt
rm -f *.csr *.srl

openssl genpkey -algorithm ED448 -out ca-ed448.key
openssl req -new -x509 -days 365 -key ca-ed448.key -out ca-ed448.crt \
    -subj "/CN=Test Ed448 CA/O=Test/C=IT"

openssl genpkey -algorithm ED448 -out server-ed448.key
openssl req -new -key server-ed448.key -out server-ed448.csr \
    -subj "/CN=localhost/O=TestServer/C=IT"
openssl x509 -req -days 365 -in server-ed448.csr \
    -CA ca-ed448.crt -CAkey ca-ed448.key -CAcreateserial -out server-ed448.crt
rm -f *.csr *.srl

echo "[3/6] Generating certificate chain..."
cd "${CERT_DIR}/chain"

openssl genrsa -out root-ca.key 4096
openssl req -new -x509 -days 730 -key root-ca.key -out root-ca.crt \
    -subj "/CN=Test Root CA/O=TestChain/C=IT"

openssl genrsa -out intermediate-ca.key 4096
openssl req -new -key intermediate-ca.key -out intermediate-ca.csr \
    -subj "/CN=Test Intermediate CA/O=TestChain/C=IT"
openssl x509 -req -days 365 -in intermediate-ca.csr \
    -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out intermediate-ca.crt
rm -f *.csr *.srl

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=localhost/O=TestServer/C=IT"
openssl x509 -req -days 365 -in server.csr \
    -CA intermediate-ca.crt -CAkey intermediate-ca.key -CAcreateserial -out server.crt
rm -f *.csr *.srl

echo "[4/6] Generating self-signed and expired certificates..."
cd "${CERT_DIR}/selfsigned"

openssl genrsa -out rsa-selfsigned.key 2048
openssl req -new -x509 -days 365 -key rsa-selfsigned.key -out rsa-selfsigned.crt \
    -subj "/CN=SelfSigned RSA/O=Test/C=IT"

openssl ecparam -name prime256v1 -genkey -out ecdsa-selfsigned.key
openssl req -new -x509 -days 365 -key ecdsa-selfsigned.key -out ecdsa-selfsigned.crt \
    -subj "/CN=SelfSigned ECDSA/O=Test/C=IT"

cd "${CERT_DIR}/expired"

openssl genrsa -out expired.key 2048
openssl req -new -key expired.key -out expired.csr \
    -subj "/CN=Expired Cert/O=Test/C=IT"
openssl x509 -req -days 0 -in expired.csr \
    -CA "${CERT_DIR}/traditional/rsa/ca-rsa2048.crt" \
    -CAkey "${CERT_DIR}/traditional/rsa/ca-rsa2048.key" \
    -CAcreateserial -out expired.crt
rm -f *.csr *.srl

echo "[5/6] Generating certificates with SAN and special types..."
cd "${CERT_DIR}/san-types"

cat > san.cnf << 'SANEOF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = IT
O = Test
CN = localhost

[ext]
basicConstraints=CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = test.local
DNS.3 = 127.0.0.1
IP.1 = 127.0.0.1
IP.2 = ::1
SANEOF

openssl req -new -newkey rsa:2048 -keyout san-rsa.key -out san-rsa.csr \
    -config san.cnf -passout pass:test
openssl x509 -req -days 365 -in san-rsa.csr \
    -CA "${CERT_DIR}/traditional/rsa/ca-rsa2048.crt" \
    -CAkey "${CERT_DIR}/traditional/rsa/ca-rsa2048.key" \
    -CAcreateserial -out san-rsa.crt -extfile san.cnf -extensions ext

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
    -out san-ecdsa.key -pass pass:test
openssl req -new -key san-ecdsa.key -out san-ecdsa.csr -config san.cnf -passin pass:test
openssl x509 -req -days 365 -in san-ecdsa.csr \
    -CA "${CERT_DIR}/traditional/ecdsa/ca-ecdsa-p256.crt" \
    -CAkey "${CERT_DIR}/traditional/ecdsa/ca-ecdsa-p256.key" \
    -CAcreateserial -out san-ecdsa.crt -extfile san.cnf -extensions ext
rm -f *.csr *.srl san.cnf

cd "${CERT_DIR}/client"

cat > client.cnf << 'CLIENTEOF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = IT
O = TestClient
CN = testclient

[ext]
basicConstraints=CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
CLIENTEOF

openssl req -new -newkey rsa:2048 -keyout client.key -out client.csr \
    -config client.cnf -passout pass:test
openssl x509 -req -days 365 -in client.csr \
    -CA "${CERT_DIR}/traditional/rsa/ca-rsa2048.crt" \
    -CAkey "${CERT_DIR}/traditional/rsa/ca-rsa2048.key" \
    -CAcreateserial -out client.crt -extfile client.cnf -extensions ext
rm -f *.csr *.srl client.cnf

cd "${CERT_DIR}/wildcard"

cat > wildcard.cnf << 'WILDCARDEOF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = IT
O = Test
CN = *.test.local

[ext]
basicConstraints=CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = *.test.local
DNS.2 = test.local
DNS.3 = *.api.test.local
WILDCARDEOF

openssl req -new -newkey rsa:2048 -keyout wildcard.key -out wildcard.csr \
    -config wildcard.cnf -passout pass:test
openssl x509 -req -days 365 -in wildcard.csr \
    -CA "${CERT_DIR}/traditional/rsa/ca-rsa2048.crt" \
    -CAkey "${CERT_DIR}/traditional/rsa/ca-rsa2048.key" \
    -CAcreateserial -out wildcard.crt -extfile wildcard.cnf -extensions ext
rm -f *.csr *.srl wildcard.cnf

echo "[6/7] Generating PKCS#12 files..."
cd "${CERT_DIR}/p12-format"

openssl pkcs12 -export -out server-rsa2048.pfx \
    -inkey "${CERT_DIR}/traditional/rsa/server-rsa2048.key" \
    -in "${CERT_DIR}/traditional/rsa/server-rsa2048.crt" \
    -CAfile "${CERT_DIR}/traditional/rsa/ca-rsa2048.crt" -passout pass:testpass

openssl pkcs12 -export -out server-ecdsa-p256.pfx \
    -inkey "${CERT_DIR}/traditional/ecdsa/server-ecdsa-p256.key" \
    -in "${CERT_DIR}/traditional/ecdsa/server-ecdsa-p256.crt" \
    -CAfile "${CERT_DIR}/traditional/ecdsa/ca-ecdsa-p256.crt" -passout pass:testpass

echo "[7/7] Generating certificates with text prefix for PEM parsing tests..."
cd "${CERT_DIR}/with-text"

cat > ca-with-text.crt << 'TEXTEOF'
Certificate for use with TLS servers
Authority: Test CA
Issuer: Test CA
TEXTEOF
cat "${CERT_DIR}/traditional/rsa/ca-rsa2048.crt" >> ca-with-text.crt

cat > ca-with-text.key << 'TEXTKEYEOF'
Private Key - RSA 2048 bit
Do not share this key
TEXTKEYEOF
cat "${CERT_DIR}/traditional/rsa/ca-rsa2048.key" >> ca-with-text.key

echo "[8/8] Decrypting password-protected keys for tests..."
cd "${CERT_DIR}/san-types"
openssl rsa -in san-rsa.key -out san-rsa.key.dec -passin pass:test 2>/dev/null && mv san-rsa.key.dec san-rsa.key || true
openssl pkcs8 -in san-ecdsa.key -out san-ecdsa.key.dec -passin pass:test -nocrypt 2>/dev/null && mv san-ecdsa.key.dec san-ecdsa.key || true

cd "${CERT_DIR}/client"
openssl rsa -in client.key -out client.key.dec -passin pass:test 2>/dev/null && mv client.key.dec client.key || true

cd "${CERT_DIR}/wildcard"
openssl rsa -in wildcard.key -out wildcard.key.dec -passin pass:test 2>/dev/null && mv wildcard.key.dec wildcard.key || true

cat > "${CERT_DIR}/.gitignore" << 'EOF'
*
!README.md
!.gitignore
EOF

cat > "${CERT_DIR}/README.md" << 'EOF'
# Test Certificates Directory

This directory contains various test certificates for testing certinfo-go.

## Structure

### traditional/
Traditional certificates using RSA and ECDSA algorithms.

- **rsa/**: RSA certificates (2048, 3072, 4096 bit)
- **ecdsa/**: ECDSA certificates (P-256, P-384, P-521, Ed25519, Ed448)

### chain/
Certificate chain (root -> intermediate -> server)

### selfsigned/
Self-signed certificates (no CA)

### expired/
Expired certificates for testing validation

### san-types/
Certificates with Subject Alternative Names (SAN)

### client/
Client certificates for mTLS testing

### wildcard/
Wildcard certificates (*.test.local)

### p12-format/
PKCS#12 format certificates (password: testpass)

### with-text/
Certificates and keys with descriptive text prefix before PEM blocks (for testing PEM parsing)

## Usage

All keys without password protection can be read directly.
Keys with `-passout pass:test` or `-passout pass:testpass` require:
- OpenSSL: `-passin pass:test`
- Go: Use `x509.DecodePKCS1PrivateKey` or `x509.ParsePKCS8PrivateKey` with decrypted key
EOF

echo ""
echo "=== Certificate generation complete! ==="
echo "Total certificates generated in: ${CERT_DIR}"
