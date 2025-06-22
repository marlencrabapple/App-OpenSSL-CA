#!/usr/bin/env bash
[[ ${SS_DEBUG:-0} -gt 0 ]] && set -x

SS_SAN="${SS_SAN:-"DNS:localhost,IP.0:127.0.0.1,IP.1:::1"}"

ssconfig=$(printf '[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nbasicConstraints=critical,CA:true\n\nsubjectKeyIdentifier=hash\n\nauthorityKeyIdentifier=keyid:always,issuer\n\nsubjectAltName=%s\n\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth' "$SS_SAN")

configfile=$(mktemp --suffix '.cnf')
printf "%s" "$ssconfig" >"$configfile"

openssl req -x509 -out "${SS_OUTFNBASE:=${1:-$(basename "$(pwd)")-localhost}}.pem" \
  -keyout "${SS_OUTFNBASE}-key.pem" -days "${SS_DAYSVALID:-90}" \
  -newkey "${SS_NEWKEYPARAMS:-rsa:2048}" \
  -nodes "-${SS_DIGEST:-"sha256"}" \
  -subj "/CN=${SS_CERTCN:="localhost SSL-TLS server"}/O=${SS_O:-$SS_CERTCN}/${SS_OU:+"OU=$SS_OU/"}" \
  -extensions EXT -config "$configfile"

status=$?
exit $status
