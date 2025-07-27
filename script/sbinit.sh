#!/usr/bin/env bash

[[ "${SBINIT_DEBUG:=${DEBUG:-0}}" -gt 0 ]] && set -x

export NAME

if [[ -z "$1" ]]; then
    echo -n "Enter a base value for the resulting keys' Common Name fields: "
    read NAME
else
    NAME="$1"
fi

#D#i=2
#D#for field in SBINIT_SUBJ_O SBINIT_SUBJ_OU; do
#echo "$([[ -n "${$field:="${$i:-"sbinit.sh@$(hostname)"}"}" ]] \
#	&& $field+="/O=\$$field")"
# i=$(( i+1 ))

#Ddone;

SUBJBASE=$(perl -e 'use v5.40; use utf8; use Sys::Hostname "hostname"; use Data::Dumper; warn Dumper([\@ARGV, $ENV{NAME}, $ENV{SBINIT_SUBJCN}, shift @ARGV, hostname]); my $cn = ($ENV{NAME} // $ENV{SBINIT_SUBJCN} // shift @ARGV // hostname); my $subj = "/CN=$cn"; my $o = ($ENV{SBINIT_SUBJO} // shift @ARGV); $o and $subj.="O=$o/"; my $ou = ($ENV{SBINIT_OU} // shift @ARGV); $ou and $subj .= "OU=$ou"; say $subj' "$@")

echo "$SUBJBASE"

OUTDIR="${SUBJBASE:=${1:-${SBINIT_SUBJCN:-$(hostname)}}} secureboot - mkkeys.sh_$(date +%s)"

mkdirout="$(
    perl -e 'use Cwd "abs_path"; use Data::Dumper; use Path::Tiny; use utf8; use v5.40; my $path = path($ARGV[0] =~ s/\//_/rg)->mkdir; warn Dumper(\@ARGV, $?, $!, $path) or $?; say $path;' "$OUTDIR" || exit $?
)"

echo "$mkdirout"

#mkdir -p "$mkdirout" || exit

(
    cd "$mkdirout" || exit

    openssl req -new -x509 -newkey rsa:2048 -subj "$SUBJBASE PK/" -keyout PK.key \
        -out PK.crt -days 3650 -nodes -sha256

    openssl req -new -x509 -newkey rsa:2048 -subj "$SUBJBASE KEK/" \
        -keyout KEK.key -out KEK.crt -days 3650 -nodes -sha256

    openssl req -new -x509 -newkey rsa:2048 -subj "$SUBJBASE db/" -keyout db.key \
        -out db.crt -days 3650 -nodes -sha256

    openssl x509 -in PK.crt -out PK.cer -outform DER
    openssl x509 -in KEK.crt -out KEK.cer -outform DER
    openssl x509 -in db.crt -out db.cer -outform DER

    GUID="$(uuidgen)"
    echo "$GUID" >myGUID.txt

    cert-to-efi-sig-list -g "$(<myGUID.txt)" PK.crt PK.esl
    cert-to-efi-sig-list -g "$(<myGUID.txt)" KEK.crt KEK.esl
    cert-to-efi-sig-list -g "$(<myGUID.txt)" db.crt db.esl

    [[ -f "noPK.esl" ]] &&
        mv noPK.esl "SENSITIVE_noPK.$(perl -e 'use Time::HiRes; printf "%d%d" Time::HiRes::gettimeofday').esl"

    touch noPK.esl

    sign-efi-sig-list -g "$(<myGUID.txt)" \
        -k PK.key -c PK.crt PK PK.esl PK.auth
    sign-efi-sig-list -g "$(<myGUID.txt)" \
        -k PK.key -c PK.crt PK noPK.esl noPK.auth
    sign-efi-sig-list -g "$(<myGUID.txt)" \
        -k PK.key -c PK.crt KEK KEK.esl KEK.auth
    sign-efi-sig-list -g "$(<myGUID.txt)" \
        -k KEK.key -c KEK.crt db db.esl db.auth

    chmod 0600 *.key
)

echo "Keys generated in: $mkdirout"
