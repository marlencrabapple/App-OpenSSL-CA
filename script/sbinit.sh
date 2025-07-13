#!/usr/bin/env hsh

if [[ -z "$1" ]]; then
  echo -n "Enter a base value for the resulting keys' Common Name fields:"
  read NAME
fi

OUTDIR="$NAME secureboot - mkkeys.sh_$(date +%s)";
mkdir "$OUTDIR" || exit

( cd "$OUTDIR" || exit

  openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$NAME PK/" -keyout PK.key \
      -out PK.crt -days 3650 -nodes -sha256

  openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$NAME KEK/"\
      -keyout KEK.key -out KEK.crt -days 3650 -nodes -sha256

  openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$NAME DB/" -keyout DB.key \
      -out DB.crt -days 3650 -nodes -sha256

  openssl x509 -in PK.crt -out PK.cer -outform DER
  openssl x509 -in KEK.crt -out KEK.cer -outform DER
  openssl x509 -in DB.crt -out DB.cer -outform DER

  GUID="$(uuidgen)"
  echo $GUID > myGUID.txt

  cert-to-efi-sig-list -g $GUID PK.crt PK.esl
  cert-to-efi-sig-list -g $GUID KEK.crt KEK.esl
  cert-to-efi-sig-list -g $GUID DB.crt DB.esl

  mv noPK.esl SENSITIVE_noPK.$(epoch).esl
  touch noPK.esl

 sign-efi-sig-list -g$GUID -t"$(date --date='1 second' +'%Y-%m-%d %H:%M:%S')" \
     -k PK.key -c PK.crt PK PK.esl PK.auth
 sign-efi-sig-list -g$GUID -t"$(date --date='1 second' +'%Y-%m-%d %H:%M:%S')" \
     -k PK.key -c PK.crt PK noPK.esl noPK.auth
 sign-efi-sig-list -g$GUID -t"$(date --date='1 second' +'%Y-%m-%d %H:%M:%S')" \
     -k PK.key -c PK.crt KEK KEK.esl KEK.auth
 sign-efi-sig-list -g$GUID -t"$(date --date='1 second' +'%Y-%m-%d %H:%M:%S')" \
     -k KEK.key -c KEK.crt db DB.esl DB.auth

  chmod 0600 *.key
)
