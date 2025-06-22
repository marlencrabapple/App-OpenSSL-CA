#!/usr/bin/env perl
use Object::Pad ':experimental(:all)';

package x509::pl 0.01;

class x509::pl;

use lib 'lib';

use utf8;
use v5.40;

use IPC::Run3;
use Const::Fast;
use Net::SSLeay;

use Data::Dumper;
use Getopt::Long;
use Syntax::Keyword::Defer;

const our %DIGESTALGO => {

    #SHA1   => 'SHA1',
    #SHA224 => 'SHA224',
    SHA256 => 'SHA256',
    SHA384 => 'SHA384',
    SHA512 => 'SHA512',
};

const our %KEYALGO => {
    RSA => {
        2048 => 'RSA:2048',
        4096 => 'RSA:4096',
    },
    EC => {
        P256 => 'EC:P-256',
        P384 => 'EC:P-384',
        P521 => 'EC:P-521',
    },
};

field $cn : param;
field $org : param(org);
field $orgunit : param(ou);

#field $outfstub : param(offnf); # ...
field $outfmt_fn : param(out_fn_fmtstr);
field $pem : param         = 1;
field $key_pw : param      = undef;
field $key_algo : param    = $KEYALGO{P521};
field $digest_also : param = $DIGESTALGO{SHA256};

field $san : param(san) //=
  { IP => [qw(127.0.0.1 ::1)], DNS => ['localhost'] };

ADJUSTPARAMS($params) {
    GetOptions( $$params{argv}->@*, 'common_name|cn=s', )
};

class CertFile {
    field $cert : param : reader   = undef;
    field $key : param : reader    = undef;
    field $pkcs12 : param : reader = undef;

    ADJUSTPARAMS($params) {
    }
}

class SAN {
    use Object::Pad ':experimental(:all)';

    field $ip : param    = [q'127.0.0.1 ::1'];
    field $dns : param   = [qw(localhost)];
    field $email : param = undef;

    ADJUSTPARAMS($params) {
        $self->doctor_SAN(%$params)
    };

    method add_ip ($ip) {
        $self->add_to_san( ip => $ip );
    }

    method doctor_SAN { $self->append_to_SAN(@_) }

    method add_to_san (%fields) {
        foreach my ( $field, $val ) (%fields) {
            $self->$field isa 'ARRAY'
              ? push $self->$field->@*, $val
              : $self->add_to_san( $field => $val );
        }
    }

    method SAN : common (%fields) {
        SAN->new( %fields{q'ip dns email'} );
    }

    method as_ASN1(%opts) {
    }

}

method create_csr : common (%fields) {
    $class->new(%fields);
}

method create_self_signed : common (%fields) {
    $class->new(%fields);
}

method setup_subordinate_ca : common (%fields) {
    $class->new(%fields);
}

method setup_root_ca : common (%fields) {
    $class->new(%fields);
}

method generate_private_key ( $out, %opts ) {
    const my %default_opts = {
        cipher => 'aes256',
        pw     =>
      }
      unless $self->config->{keyenc};
}

method certificate ($out) {

}

#ethod keyfile ($out) {
#   $out ? $key
#}

method generate_pkcs12 ( $out, $w ) {

}

#method mint_certification ($out) {
method mint_certificate ($out) {

}

#method san_fmtstr {
#    my $san    = $self->san;
#    my $fmtstr = '';
#    for my $type (qw(IP DNS)) {
#        $fmtstr .= sprintf( "%s=%s,", $type, join( ',', $san->{$type}->@* ) );
#    }
#    return $fmtstr;

#    for my ( $type, $resource ) ( $san->%* ) {
#        $fmtstr .= sprintf( "%s=%s,", $type, join( ',', $resource->@* ) );
#    }
#}
