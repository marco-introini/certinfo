#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/test_certs/postquantum"

echo "=== Post-Quantum Certificate Generation Script ==="
echo "Output directory: ${CERT_DIR}"
echo ""

if [ ! -d "${CERT_DIR}" ]; then
    mkdir -p "${CERT_DIR}"
fi

mkdir -p "${CERT_DIR}/standalone"
mkdir -p "${CERT_DIR}/hybrid"
mkdir -p "${CERT_DIR}/hybrid-rsa"
mkdir -p "${CERT_DIR}/hybrid-ecdsa"

check_pqc_available() {
    if openssl genpkey -algorithm ML_DSA -out /dev/null -pkeyopt ml_dsa_parameter_set:44 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

if ! check_pqc_available; then
    echo "WARNING: Post-Quantum Cryptography provider is not available."
    echo "This script will generate configuration templates and instructions."
    echo ""
    echo "To enable PQC, you need:"
    echo "  1. OpenSSL 3.x compiled with PQC provider support"
    echo "  2. liboqs library installed"
    echo ""
    echo "For OpenSSL 3.6+, ensure the PQC provider is loaded in openssl.cnf:"
    echo ""
    echo '  [provider_sect]'
    echo '  pqc = pqc_sect'
    echo ''
    echo '  [pqc_sect]'
    echo '  activate = 1'
    echo ""
    echo "Alternatively, you can use the -provider option:"
    echo "  openssl genpkey -provider pqc -algorithm ML_DSA ..."
    echo ""
fi

echo "[1/4] Generating ML-DSA (standalone) certificates..."

cd "${CERT_DIR}/standalone"

cat > openssl_pqc.cnf << 'PQCEOF'
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pqc = pqc_sect

[default_sect]
algorithm = default

[pqc_sect]
module = /usr/local/lib/openssl/providers/libpqc.so
active = 1
PQCEOF

if openssl genpkey -algorithm ML_DSA -out ca-mldsa44.key -pkeyopt ml_dsa_parameter_set:44 2>/dev/null; then
    echo "  - ML-DSA-44 CA generated"

    openssl req -new -x509 -days 365 -key ca-mldsa44.key -out ca-mldsa44.crt \
        -subj "/CN=Test ML-DSA-44 CA/O=PostQuantumTest/C=IT"
    echo "  - ML-DSA-44 CA certificate created"

    openssl genpkey -algorithm ML_DSA -out server-mldsa44.key -pkeyopt ml_dsa_parameter_set:44
    echo "  - ML-DSA-44 server key generated"

    openssl req -new -key server-mldsa44.key -out server-mldsa44.csr \
        -subj "/CN=localhost/O=PostQuantumServer/C=IT"
    openssl x509 -req -days 365 -in server-mldsa44.csr \
        -CA ca-mldsa44.crt -CAkey ca-mldsa44.key -CAcreateserial -out server-mldsa44.crt
    rm -f *.csr *.srl
    echo "  - ML-DSA-44 server certificate created"
else
    cat > ca-mldsa44.key << 'KEYEOF'
# ML-DSA-44 Private Key
# Not generated - PQC provider not available
# Run: openssl genpkey -algorithm ML_DSA -out ca-mldsa44.key -pkeyopt ml_dsa_parameter_set:44
KEYEOF
    cat > ca-mldsa44.crt << 'CERTEOF'
# ML-DSA-44 CA Certificate
# Not generated - PQC provider not available
# Run: openssl req -new -x509 -days 365 -key ca-mldsa44.key -out ca-mldsa44.crt
CERTEOF
    echo "  - Placeholder files created (PQC provider required)"
fi

if openssl genpkey -algorithm ML_DSA -out ca-mldsa65.key -pkeyopt ml_dsa_parameter_set:65 2>/dev/null; then
    openssl req -new -x509 -days 365 -key ca-mldsa65.key -out ca-mldsa65.crt \
        -subj "/CN=Test ML-DSA-65 CA/O=PostQuantumTest/C=IT"
    echo "  - ML-DSA-65 CA generated"
fi

if openssl genpkey -algorithm ML_DSA -out ca-mldsa87.key -pkeyopt ml_dsa_parameter_set:87 2>/dev/null; then
    openssl req -new -x509 -days 365 -key ca-mldsa87.key -out ca-mldsa87.crt \
        -subj "/CN=Test ML-DSA-87 CA/O=PostQuantumTest/C=IT"
    echo "  - ML-DSA-87 CA generated"
fi

echo "[2/4] Generating ML-KEM certificates..."

cd "${CERT_DIR}/standalone"

if openssl genpkey -algorithm ML_KEM -out ca-mlkem760.key -pkeyopt ml_kem_parameter_set:760 2>/dev/null; then
    openssl req -new -x509 -days 365 -key ca-mlkem760.key -out ca-mlkem760.crt \
        -subj "/CN=Test ML-KEM-760 CA/O=PostQuantumTest/C=IT"
    echo "  - ML-KEM-760 CA generated"
fi

if openssl genpkey -algorithm ML_KEM -out ca-mlkem1024.key -pkeyopt ml_kem_parameter_set:1024 2>/dev/null; then
    openssl req -new -x509 -days 365 -key ca-mlkem1024.key -out ca-mlkem1024.crt \
        -subj "/CN=Test ML-KEM-1024 CA/O=PostQuantumTest/C=IT"
    echo "  - ML-KEM-1024 CA generated"
fi

if openssl genpkey -algorithm ML_KEM -out ca-mlkem1760.key -pkeyopt ml_kem_parameter_set:1760 2>/dev/null; then
    openssl req -new -x509 -days 365 -key ca-mlkem1760.key -out ca-mlkem1760.crt \
        -subj "/CN=Test ML-KEM-1760 CA/O=PostQuantumTest/C=IT"
    echo "  - ML-KEM-1760 CA generated"
fi

echo "[3/4] Generating hybrid RSA + PQC certificates..."

cd "${CERT_DIR}/hybrid-rsa"

if check_pqc_available; then
    openssl genrsa -out ca-rsa.key 4096
    openssl req -new -x509 -days 365 -key ca-rsa.key -out ca-rsa.crt \
        -subj "/CN=Test Hybrid RSA+PQC CA/O=PostQuantumTest/C=IT"
    echo "  - Hybrid RSA CA generated"

    openssl genpkey -algorithm ML_DSA -out ca-mldsa.key -pkeyopt ml_dsa_parameter_set:44
    echo "  - ML-DSA key for hybrid CA generated"

    openssl genrsa -out server.key 4096
    openssl req -new -key server.key -out server.csr \
        -subj "/CN=localhost/O=HybridServer/C=IT"

    openssl x509 -req -days 365 -in server.csr \
        -CA ca-rsa.crt -CAkey ca-rsa.key -CAcreateserial -out server-rsa.crt
    rm -f *.csr *.srl
    echo "  - Hybrid RSA server certificate created"
else
    cat > ca-rsa.key << 'KEYEOF'
# Hybrid RSA+PQC CA Key
# Run: openssl genrsa -out ca-rsa.key 4096
KEYEOF
    echo "  - Placeholder created for hybrid RSA CA"
fi

echo "[4/4] Generating hybrid ECDSA + PQC certificates..."

cd "${CERT_DIR}/hybrid-ecdsa"

if check_pqc_available; then
    openssl ecparam -name prime256v1 -genkey -out ca-ecdsa.key
    openssl req -new -x509 -days 365 -key ca-ecdsa.key -out ca-ecdsa.crt \
        -subj "/CN=Test Hybrid ECDSA+PQC CA/O=PostQuantumTest/C=IT"
    echo "  - Hybrid ECDSA CA generated"

    openssl genpkey -algorithm ML_DSA -out ca-mldsa.key -pkeyopt ml_dsa_parameter_set:44
    echo "  - ML-DSA key for hybrid CA generated"

    openssl ecparam -name prime256v1 -genkey -out server.key
    openssl req -new -key server.key -out server.csr \
        -subj "/CN=localhost/O=HybridServer/C=IT"

    openssl x509 -req -days 365 -in server.csr \
        -CA ca-ecdsa.crt -CAkey ca-ecdsa.key -CAcreateserial -out server-ecdsa.crt
    rm -f *.csr *.srl
    echo "  - Hybrid ECDSA server certificate created"
else
    cat > ca-ecdsa.key << 'KEYEOF'
# Hybrid ECDSA+PQC CA Key
# Run: openssl ecparam -name prime256v1 -genkey -out ca-ecdsa.key
KEYEOF
    echo "  - Placeholder created for hybrid ECDSA CA"
fi

rm -f "${CERT_DIR}/standalone/openssl_pqc.cnf"

echo ""
echo "=== Post-Quantum Certificate Generation Complete ==="
echo "Output directory: ${CERT_DIR}"
echo ""
echo "Note: Some certificates may not have been generated if the PQC provider"
echo "is not available. Check the output above for details."
echo ""
echo "Security Levels for Post-Quantum Algorithms:"
echo "  ML-DSA-44 / ML-KEM-760  : Level 2 (NIST security level 2)"
echo "  ML-DSA-65 / ML-KEM-1024 : Level 3 (NIST security level 3)"
echo "  ML-DSA-87 / ML-KEM-1760 : Level 5 (NIST security level 5)"
