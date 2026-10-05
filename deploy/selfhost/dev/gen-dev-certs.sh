#!/bin/sh
# LOCAL TRIAL ONLY. Creates a throwaway CA and two certificates in ./certs:
# nexus.localtest (Caddy in front of Nexus) and api.resend.com (the mail sink
# that stands in for Resend). Never use these outside compose.dev.yaml.
# The CA may sign only those two names (nameConstraints, pathlen 0) and its
# key is deleted right after signing, so nothing else can ever be issued.
set -eu
umask 077
cd "$(dirname "$0")"
rm -rf certs
mkdir certs && cd certs
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj "/CN=nexus selfhost dev CA" \
  -addext "basicConstraints=critical,CA:true,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "nameConstraints=critical,permitted;DNS:nexus.localtest,permitted;DNS:api.resend.com" \
  -keyout ca.key -out ca.crt 2>/dev/null
for name in nexus.localtest api.resend.com; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$name" -keyout "$name.key" -out "$name.csr" 2>/dev/null
  printf 'basicConstraints=critical,CA:false\nsubjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$name" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 7 \
    -extfile "$name.ext" -out "$name.crt" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
done
rm -f ca.key ca.srl
# Certificates are public; keys stay 0600 (umask). Each container mounts only
# its own files read-only (dev/compose.dev.yaml); caddy and mailsink run as root.
chmod 644 ./*.crt
chmod 755 .
echo "dev certificates written to $(pwd) (CA key deleted)"
