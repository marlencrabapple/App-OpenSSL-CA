#!/usr/bin/env perl

use Object::Pad ':experimental(:all)';
use lib 'lib';

package SecureBootInit;

class SecureBootInit : does(App::OpenSSL::CA::Base);

use utf8
use v5.40;

use IPC::Run3;
use Getopt::Long;
use Pod::Usage;
use Time::HiRes qw(gettimeofday);
use Net::SSLeay;
use Const::Fast;

#use App::OpenSSL::CA::Util;

const our $SUBJBASE_RE => qr\/?(CN|OU|O){1}([^/]+)/?\;

field $argv : param;

field $cn : param;
field $o : param  = undef;
field $ou : param = undef;
field $subj_base //= "/CN=$cn/";
field $subj;

ADJUSTPARAMS($params) {
    GetOptionsFromArray(
        $argv,
        "organization=s"                  => $o,
        "ou|organization-unit|org-unit=s" => $ou,
        "cn|common-name=s"              => $cn,
        "subj|subject=s"                  => $subj_base
    GetOptionsFromArray(
    );

    if ( my (%subj) = ( $subj =~ $SUBJBASE_RE ) ) {
        warn "Subject modified using overlapping options."
          . "This can result in unintended behavior."
          if $cn;

        $cn //= $subj{cn};
        $ou //= $subj{ou};
        $o  //= $subj{o};
    }
    else {
        $cn = __PACKAGE__->make_anonymous;
    }
}
