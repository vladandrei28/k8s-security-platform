#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE="security-webhook"
NAMESPACE="default"

cd "$CERT_DIR"

echo "Generating CA..."
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -days 365 \
  -subj "/CN=k8s-security-webhook-ca" \
  -out ca.crt

echo "Writing server cert config..."
cat > server.conf <<CONF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${SERVICE}.${NAMESPACE}.svc

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVICE}
DNS.2 = ${SERVICE}.${NAMESPACE}
DNS.3 = ${SERVICE}.${NAMESPACE}.svc
DNS.4 = ${SERVICE}.${NAMESPACE}.svc.cluster.local
CONF

echo "Generating server key + CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config server.conf

echo "Signing server cert with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 \
  -extensions v3_req -extfile server.conf

echo ""
echo "Done. Verify server cert SANs:"
openssl x509 -in server.crt -noout -text | grep -A1 "Subject Alternative Name"
