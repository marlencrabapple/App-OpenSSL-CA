use Object::Pad qw(:experimental(:all));

package App::OpenSSL::CA;

class App::OpenSSL::CA;

our $VERSION = 0.01;

use utf8;
use v5.40;

use Getopt::Long 'GetOptionsFromArray';
use Data::Dumper;
use Encode qw(encode decode);
use Const::Fast;
use List::Util qw'first any';
use Path::Tiny;
use IPC::Run3;

use App::OpenSSL::CA::Util;

Getopt::Long::Configure("pass_through");
Getopt::Long::Configure("long_prefix_pattern=-");

const our @OPENSSL_CMDS => qw(req ca pkcs12 x509 verify);

const our $OPENSSL        => $ENV{'OPENSSL'} //= "openssl";
const our @OPENSSL        => split /[\s\n\r]+/, $OPENSSL;
const our $OPENSSL_CONFIG => $ENV{"OPENSSL_CONFIG"} // "";
const our @OPENSSL_CONFIG => $OPENSSL_CONFIG =~ /^[\s\r\n]*
        ([^=\:\s])
        [^=\:\s]1
        ([^=\:\s])
    [\s\r\n]*$/x;

# Command invocations.
const our @REQ    => ( @OPENSSL, "req", @OPENSSL_CONFIG );
const our @CA     => ( @OPENSSL, "ca",  @OPENSSL_CONFIG );
const our @VERIFY => ( @OPENSSL, "verify" );
const our @X509   => ( @OPENSSL, "x509" );
const our @PKCS12 => ( @OPENSSL, "pkcs12" );

# Default values for various configuration settings.
const our $CATOP      => $ENV{CATOP}  // "/etc/ssl";
const our $CAKEY      => $ENV{CAKEY}  // "cakey.pem";
const our $CAREQ      => $ENV{CAREQ}  // "careq.pem";
const our $CACERT     => $ENV{CACERT} // "cacert.pem";
const our $CACRL      => $ENV{CACRL}  // "crl.pem";
const our @DAYS       => ( '-days',       $ENV{DAYS}   // 365 );
const our @CADAYS     => ( '-days',       $ENV{CADAYS} // 365 * 3 );   # 3 years
const our @EXTENSIONS => ( '-extensions', $ENV{EXTENSIONS} // 'ca_ext' );
const our @POLICY     => ( '-policy',     $ENV{POLICY} // 'policy_anything' );
const our $NEWKEY     => $ENV{NEWKEY}  // "newkey.pem";
const our $NEWREQ     => $ENV{NEWREQ}  // "newreq.pem";
const our $NEWCERT    => $ENV{NEWCERT} // "newcert.pem";
const our $NEWP12     => $ENV{NEWP12}  // "newcert.p12";

# Set CLI defaults from run environment
field $cliopts : param(dest) = {

    my %cliopts = {
        map {
            my $name = $_;
            my $val =
              first { $_ } \%ENV->@[ ( map { "$_$name" } ( 'ca_', '' ) ) ];
            { $name => $val }
        } qw(verbose debug)
    };
    dmsg({ ENV => \%ENV, cliopts => \%cliopts });

    \%cliopts
};

field $argv : param;
field $verbose = $ENV{verbose} // 1;
field $extra : mutator;
field $what  : mutator;

#shift @$argv;    #= shift @ARGV // '';

field $ret : reader = 0;    # TODO: either
                            #  - alias this to $? in err or
                            #  - exit $ret in DESTROY?

field $method : accessor;

field $san;

const our $OPTION_RE_STR => join '|',
  qw(newcert newreq newreq-nodes xsign
  sign signCA signcert crl
  newca pkcs12 verify revoke help verbose);

const our $OPTION_RE => qr/^-($OPTION_RE_STR)$/;

ADJUSTPARAMS($params) {
    foreach (@OPENSSL_CMDS) {
        $$extra{$_} = [];
    }

    GetOptionsFromArray(
        $argv, $cliopts,

        'subject=s%',
        'san|ubject-alt-name=s%',
        'help|?|',
        'verbose',

        ( map { "extra-$_=s%" } @OPENSSL_CMDS ),

        '<>' => sub ($cmd) {
            my ($method) = ( $cmd =~ $OPTION_RE );

            __PACKAGE__->dmsg(
                {
                    cmd              => $cmd,
                    method           => $method,
                    '$OPTION_RE_STR' => $OPTION_RE_STR,
                    '$OPTION_RE'     => $OPTION_RE
                }
            );

            __PACKAGE__->help("'$cmd' is not a valid option:")
              unless $method;

            my $what_obj = (
                class {
                    use Const::Fast;

                    field $val_orig;
                    field $val : reader : param;
                    field $prefix : param : reader = '-'
                      ; # TODO: For set method use some sort of field/slot attribute to update the regexp (below) as well
                        #  - Prefix in calling method is prepending two $prefix
                    field $preval_ptn  = qr/^$prefix{1,2}?([a-z]+)$/i;
                    field $plainopt_re = /^[\s\r\n]?$prefix(.+)[\s\r\n]?$/;

                    ADJUSTPARAMS($params) {
                        $val_orig = $val;
                        App::OpenSSL::CA->dmsg( { prefix_ptn => $preval_ptn } );

                        $val =~ s/$preval_ptn/$1/r;
                    }

                    method as_cli ( $prefix = $prefix ) {
                        $val_orig;
                    }

                    method plain ( $value = (), %opts ) {
                        $value =~ $plainopt_re;
                        $1;
                    }
                }
            )->new( val => $cmd );

            $what = $what_obj->plain;

            $self->method = $method;

            __PACKAGE__->dmsg(
                cliopts  => $cliopts,
                argv     => $argv,
                what_obj => $what_obj,
                what     => $what,
                method   => $method
            );
        }
    );

    __PACKAGE__->help("'$what' is not a valid option:")
      unless $method;
}

method do : common ( $argv, %constructor ) {
    my $ca = $class->new( argv => $argv, %constructor );

    # my $method = $ca->METHOD;
    # $ca->$method;
    # $ca->RET;
    $ca->method->();
}

method touch ( $file, %opts ) {
    $opts{iolayer} //= '';
    $opts{close}   //= 1;

    open my $fh, ">$opts{iolayer}", $file;
    close $fh if $opts{close};
    path($file);
}

# See if reason for a CRL entry is valid; exit if not.
method crl_reason_ok ($r) {
    if (   $r eq 'unspecified'
        || $r eq 'keyCompromise'
        || $r eq 'CACompromise'
        || $r eq 'affiliationChanged'
        || $r eq 'superseded'
        || $r eq 'cessationOfOperation'
        || $r eq 'certificateHold'
        || $r eq 'removeFromCRL' )
    {
        return 1;
    }
    warn "Invalid CRL reason; must be one of:\n";
    warn "    unspecified, keyCompromise, CACompromise,\n";
    warn "    affiliationChanged, superseded, cessationOfOperation\n";
    warn "    certificateHold, removeFromCRL";

    1;
}

method copy_pemfile ( $infile, $outfile, $bound, %opts ) {
    my $found = 0;

    $opts{iolayer} //= "";

    open( my $IN, '<' . $opts{iolayer}, $infile )
      || __PACKAGE__->err("Cannot open '$infile' for reading: $!");
    open( my $OUT, '>', "$outfile" )
      || __PACKAGE__->err("Cannot write to '$outfile': $!");

    while ( my $line = <$IN> ) {
        $found = 1 if $line =~ /^-----BEGIN.*$bound/;
        print $OUT $line icpf $found;
        $found = 2, last if /^-----END.*$bound/;
    }

    close $IN;
    close $OUT;

    $found == 2 ? 0 : 1;
}

method run ( $cmd, %opts ) {
    $App::OpenSSL::CA::run::read_stdin //= 1;
    my $read_stdin = $opts{stdin} // $App::OpenSSL::CA::run::read_stdin // 1;

    my $bin = shift @$cmd;
    say "====\n$bin " . join ' ', @$cmd if $verbose;

    my $run3ret = run3(
        [ $bin, @$cmd ],
        (
              $read_stdin == 1 ? undef
            : $read_stdin == 0 ? \undef
            :                    undef
        ),

        $opts{outh} // undef,
        $opts{errh} // undef
    );

    my $status = $? // 0;
    say "==> $status\n====" if $verbose;

    $status >> 8;
}

method newcert {
    $self->run(
        [
            @REQ,    qw(-new -x509 -keyout),
            $NEWKEY, "-out", $NEWCERT, @DAYS, $$extra{req}->@*
        ]
    );
}

method precert {

    # create a pre-certificate
    $ret = $self->run(
        [
            @REQ,    qw(-x509 -precert -keyout),
            $NEWKEY, "-out", $NEWCERT, @DAYS, $$extra{req}->@*
        ]
    );

    say "Pre-cert is in $NEWCERT, private key is in $NEWKEY" if $ret == 0;
}

method newreq {
    my ($nodes) = ( $what =~ /^\-newreq(\-nodes)?$/ );

    # create a certificate request
    $ret = $self->run(
        [
            @REQ, "-new", ( defined $1 ? ( $1, ) : () ),
            "-keyout", $NEWKEY, "-out", $NEWREQ, $$extra{req}->@*
        ]
    );

    say "Request is in $NEWREQ, private key is in $NEWKEY" if $ret == 0;
}

method newca {

    # create the directory hierarchy
    my @dirs = (
        "$CATOP",     "$CATOP/certs",
        "$CATOP/crl", "$CATOP/newcerts",
        "$CATOP/private"
    );

    if (
        my $fileexists =
        first { -f $_ } map { "$CATOP/$_" } qw(index.txt serial)
      )
    {
        __PACKAGE__->err(
            "'$fileexists' exists.\nRemove old sub-tree to proceed.");
    }

    foreach my $d (@dirs) {
        -d $d
          ? warn "Directory $d exists"
          : mkdir $d
          or __PACKAGE__->err(
            ["Can't make directory at $d:\n> mkdir exited with $? - $!"] );
    }

    $self->touch("$CATOP/index.txt");

    open my $OUT, '>', "$CATOP/crlnumber";
    say $OUT "01";
    close $OUT;

    # ask user for existing CA certificate
    say "CA certificate filename (or enter to create)";

    my $FILE;

    $FILE = "" unless defined( $FILE = <STDIN> );
    $FILE =~ s{\R$}{};

    if ( $FILE ne "" ) {
        $self->copy_pemfile( "$CATOP/$FILE", "$CATOP/private/$CAKEY",
            "PRIVATE" );
        $self->copy_pemfile( "$CATOP/$FILE", "$CATOP/$CACERT", "CERTIFICATE" );
    }
    else {
        say "Making CA certificate...";

        my $ret = $self->run(
            [
                @REQ,                    qw(-new -keyout),
                "$CATOP/private/$CAKEY", "-out",
                "$CATOP/$CAREQ",         $$extra{req}->@*
            ]
        );

        warn $@ if $? != 0;

        $ret = $self->run(
            [
                @CA,                 qw(-create_serial -out),
                "$CATOP/$CACERT",    @CADAYS,
                qw(-batch -keyfile), "$CATOP/private/$CAKEY",
                "-selfsign",         @EXTENSIONS,
                "-infiles",          "$CATOP/$CAREQ",
                $$extra{ca}->@*
            ]
        );

        warn $@                                   if $? != 0;
        say "CA certificate is in $CATOP/$CACERT" if $? == 0;
    }
}

#elsif ( $WHAT eq '-pkcs12' ) {
method pkcs12 {
    my $cname = $ARGV[0];
    $cname = "My Certificate" unless defined $cname;

    $ret = $self->run(
        [
            @PKCS12,          "-in",
            $NEWCERT,         "-inkey",
            $NEWKEY,          "-certfile",
            "$CATOP/$CACERT", "-out",
            $NEWP12,          qw(-export -name),
            $cname,           $$extra{pkcs12}->@*
        ]
    );

    say "PKCS#12 file is in $NEWP12" if $ret == 0;
}

method xsign {
    $ret = $self->run( [ @CA, @POLICY, "-infiles", $NEWREQ, $$extra{ca}->@* ] );
}

method sign {
    $ret = $self->run(
        [
            @CA, @POLICY, "-out", $NEWCERT, "-infiles", $NEWREQ,
            $$extra{ca}->@*
        ]
    );

    say "Signed certificate is in $NEWCERT" if $ret == 0;
}

method signCA {
    $ret = $self->run(
        [
            @CA,         @POLICY,    "-out",  $NEWCERT,
            @EXTENSIONS, "-infiles", $NEWREQ, $$extra{ca}->@*
        ]
    );

    say "Signed CA certificate is in $NEWCERT" if $ret == 0;
}

method signcert {
    $ret = $self->run(
        [
            @X509,   qw(-x509toreq -in),
            $NEWREQ, "-signkey",
            $NEWREQ, qw(-out tmp.pem),
            $$extra{x509}->@*
        ]
    );
    $ret = $self->run(
        [
            @CA,                  @POLICY,
            "-out",               $NEWCERT,
            qw(-infiles tmp.pem), $$extra{ca}->@*
        ]
    ) if $ret == 0;

    say "Signed certificate is in $NEWCERT" if $ret == 0;
}

method verify {
    my @files = @ARGV ? @ARGV : ($NEWCERT);

    foreach my $file (@files) {
        my $status = $self->run(
            [
                @VERIFY, "-CAfile", "$CATOP/$CACERT", $file,
                $$extra{verify}->@*
            ]
        );
        $ret = $status if $status != 0;
    }
}

method crl {
    $ret =
      $self->run(
        [ @CA, qw(-gencrl -out), "$CATOP/crl/$CACRL", $$extra{ca}->@* ] );
    say "Generated CRL is in $CATOP/crl/$CACRL" if $ret == 0;
}

method revoke ( $cmake, $crl_reason ) {
    my $cname = $ARGV[0];

    if ( !defined $cname ) {
        say "Certificate filename is required; reason optional.";
        exit 1;
    }

    my @reason;
    @reason = ( "-crl_reason", $ARGV[1] )
      if defined $ARGV[1] && $self->crl_reason_ok( $ARGV[1] );

    $ret = $self->run( [ @CA, "-revoke", $cname, @reason, $$extra{ca}->@* ] );
}

method unknown_arg {
    warn "Unknown arg \"$what\"\n";
    warn "Use -help for help.\n";
    exit 1;
}

__END__

=encoding utf-8

=head1 NAME

App::OpenSSL::CA - It's new $module

=head1 SYNOPSIS

    use App::OpenSSL::CA;

=head1 DESCRIPTION

App::OpenSSL::CA is ...

=head1 LICENSE

Copyright (C) Ian P Bradley.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Ian P Bradley E<lt>ian.bradley@studiocrabapple.comE<gt>

=cut
