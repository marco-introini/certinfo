#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -d "/output" ]; then
    CERT_DIR="/output"
else
    CERT_DIR="${SCRIPT_DIR}/test_certs/postquantum"
fi

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
    if openssl genpkey -algorithm MLDSA44 -out /dev/null 2>/dev/null; then
        return 0
    elif openssl genpkey -algorithm mldsa44 -out /dev/null 2>/dev/null; then
        return 0
    elif openssl genpkey -algorithm ML_DSA -out /dev/null -pkeyopt ml_dsa_parameter_set:44 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

if ! check_pqc_available; then
    echo "WARNING: Post-Quantum Cryptography provider is not available."
    echo "This script requires OpenSSL with PQC support."
fi

pqc_genpkey() {
    if openssl genpkey -algorithm MLDSA44 "$@" 2>/dev/null; then
        return 0
    elif openssl genpkey -algorithm mldsa44 "$@" 2>/dev/null; then
        return 0
    elif openssl genpkey -algorithm ML_DSA "$@" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

echo "[1/4] Generating ML-DSA (standalone) certificates..."

cd "${CERT_DIR}/standalone"

if pqc_genpkey -out ca-mldsa44.key -pkeyopt ml_dsa_parameter_set:44 2>/dev/null || \
   openssl genpkey -algorithm mldsa44 -out ca-mldsa44.key 2>/dev/null; then
    echo "  - ML-DSA-44 CA generated"

    openssl req -new -x509 -days 365 -key ca-mldsa44.key -out ca-mldsa44.crt \
        -subj "/CN=Test ML-DSA-44 CA/O=PostQuantumTest/C=IT"
    echo "  - ML-DSA-44 CA certificate created"

    if pqc_genpkey -out server-mldsa44.key -pkeyopt ml_dsa_parameter_set:44 2>/dev/null || \
       openssl genpkey -algorithm mldsa44 -out server-mldsa44.key 2>/dev/null; then
        echo "  - ML-DSA-44 server key generated"
    fi

    openssl req -new -key server-mldsa44.key -out server-mldsa44.csr \
        -subj "/CN=localhost/O=PostQuantumServer/C=IT"
    openssl x509 -req -days 365 -in server-mldsa44.csr \
        -CA ca-mldsa44.crt -CAkey ca-mldsa44.key -CAcreateserial -out server-mldsa44.crt
    rm -f *.csr *.srl
    echo "  - ML-DSA-44 server certificate created"
else
    echo "  - Failed to generate ML-DSA-44 keys"
fi

if pqc_genpkey -out ca-mldsa65.key -pkeyopt ml_dsa_parameter_set:65 2>/dev/null || \
   openssl genpkey -algorithm MLDSA65 -out ca-mldsa65.key 2>/dev/null || \
   openssl genpkey -algorithm mldsa65 -out ca-mldsa65.key 2>/dev/null; then
    openssl req -new -x509 -days 365 -key ca-mldsa65.key -out ca-mldsa65.crt \
        -subj "/CN=Test ML-DSA-65 CA/O=PostQuantumTest/C=IT"
    echo "  - ML-DSA-65 CA generated"
fi

if pqc_genpkey -out ca-mldsa87.key -pkeyopt ml_dsa_parameter_set:87 2>/dev/null || \
   openssl genpkey -algorithm MLDSA87 -out ca-mldsa87.key 2>/dev/null || \
   openssl genpkey -algorithm mldsa87 -out ca-mldsa87.key 2>/dev/null; then
    openssl req -new -x509 -days 365 -key ca-mldsa87.key -out ca-mldsa87.crt \
        -subj "/CN=Test ML-DSA-87 CA/O=PostQuantumTest/C=IT"
    echo "  - ML-DSA-87 CA generated"
fi

echo "[2/4] Generating ML-KEM keys (for key encapsulation, not certificates)..."

cd "${CERT_DIR}/standalone"

if openssl genpkey -algorithm ML_KEM -out ca-mlkem760.key -pkeyopt ml_kem_parameter_set:760 2>/dev/null || \
   openssl genpkey -algorithm mlkem768 -out ca-mlkem760.key 2>/dev/null; then
    echo "  - ML-KEM-760 key generated"
fi

if openssl genpkey -algorithm ML_KEM -out ca-mlkem1024.key -pkeyopt ml_kem_parameter_set:1024 2>/dev/null || \
   openssl genpkey -algorithm mlkem1024 -out ca-mlkem1024.key 2>/dev/null; then
    echo "  - ML-KEM-1024 key generated"
fi

echo ""
echo "[3/4] Generating hybrid RSA + PQC certificates..."

cd "${CERT_DIR}/hybrid-rsa"

if check_pqc_available; then
    openssl genrsa -out ca-rsa.key 4096
    openssl req -new -x509 -days 365 -key ca-rsa.key -out ca-rsa.crt \
        -subj "/CN=Test Hybrid RSA+PQC CA/O=PostQuantumTest/C=IT"
    echo "  - Hybrid RSA CA generated"

    if pqc_genpkey -out ca-mldsa.key -pkeyopt ml_dsa_parameter_set:44 2>/dev/null || \
       openssl genpkey -algorithm mldsa44 -out ca-mldsa.key 2>/dev/null; then
        echo "  - ML-DSA key for hybrid CA generated"
    fi

    openssl genrsa -out server.key 4096
    openssl req -new -key server.key -out server.csr \
        -subj "/CN=localhost/O=HybridServer/C=IT"

    openssl x509 -req -days 365 -in server.csr \
        -CA ca-rsa.crt -CAkey ca-rsa.key -CAcreateserial -out server-rsa.crt
    rm -f *.csr *.srl
    echo "  - Hybrid RSA server certificate created"
else
    echo "  - PQC not available, skipping hybrid RSA"
fi

echo ""
echo "[4/4] Generating hybrid ECDSA + PQC certificates..."

cd "${CERT_DIR}/hybrid-ecdsa"

if check_pqc_available; then
    openssl ecparam -name prime256v1 -genkey -out ca-ecdsa.key
    openssl req -new -x509 -days 365 -key ca-ecdsa.key -out ca-ecdsa.crt \
        -subj "/CN=Test Hybrid ECDSA+PQC CA/O=PostQuantumTest/C=IT"
    echo "  - Hybrid ECDSA CA generated"

    if pqc_genpkey -out ca-mldsa.key -pkeyopt ml_dsa_parameter_set:44 2>/dev/null || \
       openssl genpkey -algorithm mldsa44 -out ca-mldsa.key 2>/dev/null; then
        echo "  - ML-DSA key for hybrid CA generated"
    fi

    openssl ecparam -name prime256v1 -genkey -out server.key
    openssl req -new -key server.key -out server.csr \
        -subj "/CN=localhost/O=HybridServer/C=IT"

    openssl x509 -req -days 365 -in server.csr \
        -CA ca-ecdsa.crt -CAkey ca-ecdsa.key -CAcreateserial -out server-ecdsa.crt
    rm -f *.csr *.srl
    echo "  - Hybrid ECDSA server certificate created"
else
    echo "  - PQC not available, skipping hybrid ECDSA"
fi

echo ""
echo "=== Generation Complete ==="
echo "Certificates in: ${CERT_DIR}"
