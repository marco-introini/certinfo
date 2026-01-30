#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/test_certs/postquantum"

mkdir -p "${CERT_DIR}"

echo "=== Generating Post-Quantum Certificates via Docker ==="
echo "Output directory: ${CERT_DIR}"
echo ""

if [ ! -f "${SCRIPT_DIR}/Dockerfile.pqc-gen" ]; then
    echo "ERROR: Dockerfile.pqc-gen not found in ${SCRIPT_DIR}"
    exit 1
fi

docker build -t certinfo-pqc-gen -f "${SCRIPT_DIR}/Dockerfile.pqc-gen" "${SCRIPT_DIR}" >/dev/null 2>&1

docker run --rm \
    -v "${CERT_DIR}:/output" \
    certinfo-pqc-gen

echo ""
echo "=== Generation Complete ==="
echo "Certificates generated in: ${CERT_DIR}"
echo ""
echo "Generated files:"
find "${CERT_DIR}" -name "*.crt" -o -name "*.key" 2>/dev/null | sort | head -30
echo ""
echo "To verify certificates, use:"
echo "  docker run --rm -v ${CERT_DIR}:/certs openquantumsafe/oqs-ossl3:latest \\"
echo "    openssl x509 -in /certs/standalone/ca-mldsa44.crt -text -noout"
