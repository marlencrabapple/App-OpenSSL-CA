use Object::Pad qw(:experimental(:all));

package App::OpenSSL::CA;

class App::OpenSSL::CA : does(App::OpenSSL::CA::Base);

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
use Data::Dumper;

Getopt::Long::Configure("pass_through");
Getopt::Long::Configure("long_prefix_pattern=-");

const our @OPENSSL_CMDS => qw(req ca pkcs12 x509 verify);

const our $openssl => $ENV{'OPENSSL'} // "openssl";
$ENV{'OPENSSL'} = $openssl;
const our @openssl => split_val($openssl);

const our $OPENSSL_CONFIG => $ENV{"OPENSSL_CONFIG"} // "";
const our @OPENSSL_CONFIG => split_val($OPENSSL_CONFIG);

# Command invocations.
const our @REQ    => ( @openssl, "req", @OPENSSL_CONFIG );
const our @CA     => ( @openssl, "ca",  @OPENSSL_CONFIG );
const our @VERIFY => ( @openssl, "verify" );
const our @X509   => ( @openssl, "x509" );
const our @PKCS12 => ( @openssl, "pkcs12" );

# Default values for various configuration settings.
const our $CATOP      => $ENV{CATOP}  // "/etc/ssl";
const our $CAKEY      => $ENV{CAKEY}  // "cakey.pem";
const our $CAREQ      => $ENV{CAREQ}  // "careq.pem";
const our $CACERT     => $ENV{CACERT} // "cacert.pem";
const our $CACRL      => $ENV{CACRL}  // "crl.pem";
const our @DAYS       => ( '-days',       $ENV{DAYS}   // 365 );
const our @CADAYS     => ( '-days',       $ENV{CADAYS} // 365 * 3 );   # 3 years
const our @EXTENSIONS => ( '-extensions', $ENV{EXTENSIONS} // 'v3_ca' );
const our @POLICY     => ( '-policy',     $ENV{POLICY} // 'policy_anything' );
const our $NEWKEY     => $ENV{NEWKEY}  // "newkey.pem";
const our $NEWREQ     => $ENV{NEWREQ}  // "newreq.pem";
const our $NEWCERT    => $ENV{NEWCERT} // "newcert.pem";
const our $NEWP12     => $ENV{NEWP12}  // "newcert.p12";

# Commandline parsing
field $EXTRA : mutator;
field $WHAT;            #= shift @ARGV // '';
field $argv : param;    #= @ARGV = parse_extra(@ARGV);
field $RET : reader = 0;
field $METHOD : accessor;
field $verbose = $ENV{verbose} // 1;

const our $OPTION_RE_STR => join '|',
  qw(newcert newreq newreq-nodes xsign
  sign signCA signcert crl
  newca pkcs12 verify revoke help verbose);

const our $OPTION_RE => qr/^-($OPTION_RE_STR)$/;

warn Dumper(
    { '$OPTION_RE_STR' => $OPTION_RE_STR, '$OPTION_RE' => $OPTION_RE } )
  if $ENV{DEBUG};

ADJUSTPARAMS($params) {
    foreach (@OPENSSL_CMDS) {
        $$EXTRA{$_} = [];
    }

    GetOptionsFromArray(
        $argv, $EXTRA,

        ( map { "extra-$_=s" } @OPENSSL_CMDS ),

        '<>' => sub ($cmd) {
            my ($method) = ( $cmd =~ $OPTION_RE );

            $self->help("'$cmd' is not a valid option:")
              unless $method;

            $WHAT   = $cmd;
            $METHOD = $method;
        }
    );
}

method do : common ($argv, %constructor) {
    my $ca     = $class->new( argv => $argv, %constructor );
    my $method = $ca->METHOD;
    $ca->$method;
    $ca->RET;
}

method touch ( $file, %opts ) {
    $opts{iolayer} //= '';
    $opts{close}   //= 1;

    open my $fh, ">$opts{iolayer}", $file;
    close $fh if $opts{close};
    path($file);
}

sub split_val ( $val, @args ) {

    #return split_val_win32( $val, @args ) if ( $^O eq 'MSWin32' );
    my ( @ret, @frag );

    # Skip leading whitespace
    $val =~ m{\A[ \t]*}ogc;

    # Unix shell-compatible split
    #
    # Handles backslash escapes outside quotes and
    # in double-quoted strings.  Parameter and
    # command-substitution is silently ignored.
    # Bare newlines outside quotes and (trailing) backslashes are disallowed.

    while (1) {
        last if ( pos($val) == length($val) );

        # The first char is never a SPACE or TAB.  Possible matches are:
        # 1. Ordinary string fragment
        # 2. Single-quoted string
        # 3. Double-quoted string
        # 4. Backslash escape
        # 5. Bare backlash or newline (rejected)
        #
        if ( $val =~ m{\G([^'" \t\n\\]+)}ogc ) {

            # Ordinary string
            push @frag, $1;
        }
        elsif ( $val =~ m{\G'([^']*)'}ogc ) {

            # Single-quoted string
            push @frag, $1;
        }
        elsif ( $val =~ m{\G"}ogc ) {

            # Double-quoted string
            push @frag, "";
            while (1) {
                last if ( $val =~ m{\G"}ogc );
                if ( $val =~ m{\G([^"\\]+)}ogcs ) {

                    # literals
                    push @frag, $1;
                }
                elsif ( $val =~ m{\G.(["\`\$\\])}ogc ) {

                    # backslash-escaped special
                    push @frag, $1;
                }
                elsif ( $val =~ m{\G.(.)}ogcs ) {

                    # backslashed non-special
                    push @frag, "\\$1" unless $1 eq "\n";
                }
                else {
                    die sprintf( "Malformed quoted string: %s\n", $val );
                }
            }
        }
        elsif ( $val =~ m{\G\\(.)}ogc ) {

            # Backslash is unconditional escape outside quoted strings
            push @frag, $1 unless $1 eq "\n";
        }
        else {
            die sprintf( "Bare backslash or newline in: '%s'\n", $val );
        }

        # Done if at SPACE, TAB or end, otherwise continue current fragment
        #
        next unless ( $val =~ m{\G(?:[ \t]+|\z)}ogcs );
        push @ret, join( "", splice(@frag) ) if ( @frag > 0 );
    }

    # Handle final fragment
    push @ret, join( "", splice(@frag) ) if ( @frag > 0 );
    @ret;
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
      || die "Cannot open $infile, $!";
    open( my $OUT, '>', "$outfile" ) || die "Cannot write to $outfile, $!";

    while (<$IN>) {
        $found = 1    if /^-----BEGIN.*$bound/;
        print $OUT $_ if $found;
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

method help ( $error = "" ) {
    my $caller = [ caller 0 ];

    warn "$error $$caller[0]:$$caller[1] line " . __LINE__ . "\n\n" if $error;
    warn Dumper( { caller => $caller, ( $error ? ( error => $error ) : () ) } )
      if $ENV{DEBUG};

    warn <<EOF;
Usage:
    CA.pl -newcert | -newreq | -newreq-nodes | -xsign | -sign | -signCA | -signcert | -crl | -newca [-extra-cmd parameter]
    CA.pl -pkcs12 [certname]
    CA.pl -verify certfile ...
    CA.pl -revoke certfile [reason]
EOF
    exit 0;
}

method newcert {
    $self->exec(
        [
            @REQ,    qw(-new -x509 -keyout),
            $NEWKEY, "-out", $NEWCERT, @DAYS, $$EXTRA{req}->@*
        ]
    );
}

method precert {

    # create a pre-certificate
    $RET = $self->run(
        [
            @REQ,    qw(-x509 -precert -keyout),
            $NEWKEY, "-out", $NEWCERT, @DAYS, $$EXTRA{req}->@*
        ]
    );

    say "Pre-cert is in $NEWCERT, private key is in $NEWKEY" if $RET == 0;
}

method newreq {
    my ($nodes) = ( $WHAT =~ /^\-newreq(\-nodes)?$/ );

    # create a certificate request
    $RET = $self->run(
        [
            @REQ, "-new", ( defined $1 ? ( $1, ) : () ),
            "-keyout", $NEWKEY, "-out", $NEWREQ, $$EXTRA{req}->@*
        ]
    );

    say "Request is in $NEWREQ, private key is in $NEWKEY" if $RET == 0;
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
        die "'$fileexists' exists.\nRemove old sub-tree to proceed.";
    }

    foreach my $d (@dirs) {
        -d $d
          ? warn "Directory $d exists"
          : mkdir $d
          or die "Can't mkdir $d, $!";
    }

    $self->touch("$CATOP/crlnumber");

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

        my $RET = $self->run(
            [
                @REQ,                    qw(-new -keyout),
                "$CATOP/private/$CAKEY", "-out",
                "$CATOP/$CAREQ",         $$EXTRA{req}->@*
            ]
        );

        warn $@ if $? != 0;

        $RET = $self->run(
            [
                @CA,                 qw(-create_serial -out),
                "$CATOP/$CACERT",    @CADAYS,
                qw(-batch -keyfile), "$CATOP/private/$CAKEY",
                "-selfsign",         @EXTENSIONS,
                "-infiles",          "$CATOP/$CAREQ",
                $$EXTRA{ca}->@*
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

    $RET = $self->run(
        [
            @PKCS12,          "-in",
            $NEWCERT,         "-inkey",
            $NEWKEY,          "-certfile",
            "$CATOP/$CACERT", "-out",
            $NEWP12,          qw(-export -name),
            $cname,           $$EXTRA{pkcs12}->@*
        ]
    );

    say "PKCS#12 file is in $NEWP12" if $RET == 0;
}

method xsign {
    $RET = $self->run( [ @CA, @POLICY, "-infiles", $NEWREQ, $$EXTRA{ca}->@* ] );
}

method sign {
    $RET = $self->run(
        [
            @CA, @POLICY, "-out", $NEWCERT, "-infiles", $NEWREQ,
            $$EXTRA{ca}->@*
        ]
    );

    say "Signed certificate is in $NEWCERT" if $RET == 0;
}

method signCA {
    $RET = $self->run(
        [
            @CA,         @POLICY,    "-out",  $NEWCERT,
            @EXTENSIONS, "-infiles", $NEWREQ, $$EXTRA{ca}->@*
        ]
    );

    say "Signed CA certificate is in $NEWCERT" if $RET == 0;
}

method signcert {
    $RET = $self->run(
        [
            @X509,   qw(-x509toreq -in),
            $NEWREQ, "-signkey",
            $NEWREQ, qw(-out tmp.pem),
            $$EXTRA{x509}->@*
        ]
    );
    $RET = $self->run(
        [
            @CA,                  @POLICY,
            "-out",               $NEWCERT,
            qw(-infiles tmp.pem), $$EXTRA{ca}->@*
        ]
    ) if $RET == 0;

    say "Signed certificate is in $NEWCERT" if $RET == 0;
}

method verify {
    my @files = @ARGV ? @ARGV : ($NEWCERT);

    foreach my $file (@files) {
        my $status = $self->run(
            [
                @VERIFY, "-CAfile", "$CATOP/$CACERT", $file,
                $$EXTRA{verify}->@*
            ]
        );
        $RET = $status if $status != 0;
    }
}

method crl {
    $RET =
      $self->run(
        [ @CA, qw(-gencrl -out), "$CATOP/crl/$CACRL", $$EXTRA{ca}->@* ] );
    say "Generated CRL is in $CATOP/crl/$CACRL" if $RET == 0;
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

    $RET = $self->run( [ @CA, "-revoke", $cname, @reason, $$EXTRA{ca}->@* ] );
}

method unknown_arg {
    warn "Unknown arg \"$WHAT\"\n";
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
