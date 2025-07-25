#!/usr/bin/env bash
[[ "${SBINIT_DEBUG:=${DEBUG:-0}}" -gt 0 ]] && set -x;

if [[ -z "$1" ]]; then
  echo -n "Enter a base value for the resulting keys' Common Name fields:"
  read NAME
fi

#D#i=2
#D#for field in SBINIT_SUBJ_O SBINIT_SUBJ_OU; do
  #echo "$([[ -n "${$field:="${$i:-"sbinit.sh@$(hostname)"}"}" ]] \
#	&& $field+="/O=\$$field")"
 # i=$(( i+1 ))
 
#Ddone;

SUBJ_BASE=$(perl -e 'use v5.40; use utf8; my $cn = ($ENV{NAME} // $ENV{SBINIT_SUBJCN} // (shift @ARGV)); my $subj = "/CN=$cn/"; my $o = ($ENV{SBINIT_SUBJO} // (shift @ARGV)); $o and $subj.="O=$o/"; my $ou = ($ENV{SBINIT_OU} // shift @ARGV); $ou and $subj .= "OU=$ou"; say $subj' "$@")

echo "$SUBJ_BASE"
OUTDIR="${SUBJ_BASE:=${1:-${SBINIT_SUBJCN:-$(hostname)}}} secureboot - mkkeys.sh_$(date +%s)";
mkdirout=$(perl -e 'use Cwd "abs_path"; use Data::Dumper; use Path::Tiny; use utf8; use v5.40; path(abs_path(join "", grep { $_ !~ /[-]{1,2}/ } @ARGV))->mkdir;  warn Dumper(\@ARGV); exit $?;' "$OUTDIR" || exit)

mkdir -p "$OUTDIR" || exit

( cd "$OUTDIR" || exit

  openssl req -new -x509 -newkey rsa:2048 -subj "$SUBJ_BASE PK/" -keyout PK.key \
      -out PK.crt -days 3650 -nodes -sha256

  openssl req -new -x509 -newkey rsa:2048 -subj "$SUBJ_BASE KEK/"\
      -keyout KEK.key -out KEK.crt -days 3650 -nodes -sha256

  openssl req -new -x509 -newkey rsa:2048 -subj "$SUBJ_BASE DB/" -keyout DB.key \
      -out DB.crt -days 3650 -nodes -sha256

  openssl x509 -in PK.crt -out PK.cer -outform DER
  openssl x509 -in KEK.crt -out KEK.cer -outform DER
  openssl x509 -in DB.crt -out DB.cer -outform DER

  GUID="$(uuidgen)"
  echo $GUID > myGUID.txt

  cert-to-efi-sig-list -g "$(< myGUID.txt)" PK.crt PK.esl
  cert-to-efi-sig-list -g "$(< myGUID.txt)" KEK.crt KEK.esl
  cert-to-efi-sig-list -g "$(< myGUID.txt)" DB.crt DB.esl

  [[ -f "noPK.esl" ]] && mv noPK.esl SENSITIVE_noPK.$(perl -e 'use Time::HiRes; printf "%d%d" Time::HiRes::gettimeofday').esl

  touch noPK.esl

 sign-efi-sig-list -g "$(< myGUID.txt)"  \
     -k PK.key -c PK.crt PK PK.esl PK.auth
 sign-efi-sig-list -g "$(< myGUID.txt)"  \
     -k PK.key -c PK.crt PK noPK.esl noPK.auth
 sign-efi-sig-list -g "$(< myGUID.txt)"  \
     -k PK.key -c PK.crt KEK KEK.esl KEK.auth
 sign-efi-sig-list -g "$(< myGUID.txt)"  \
     -k KEK.key -c KEK.crt db DB.esl DB.auth

  chmod 0600 *.key
)
