use Object::Pad qw(:experimental(:all));

package App::OpenSSL::CA;

class App::OpenSSL::CA : does(App::OpenSSL::CA::Base);

use utf8;
use v5.40;

use Const::Fast;
use List::Util qw'first any';
use IPC::Run3;
use Data::Dumper;

use App::OpenSSL::CA::Util;

our $VERSION = 0.01;

const our $verbose      => $ENV{VERBOSE} // 1;
const our @OPENSSL_CMDS => qw'req ca pkcs12 x509 verify';

const our $openssl => $ENV{OPENSSL} = $ENV{OPENSSL} // 'openssl';
const our $OPENSSL_CONFIG => $ENV{OPENSSL_CONFIG} // '';

# Command invocations.
const our @REQ    => ( $openssl, 'req', $OPENSSL_CONFIG );
const our @CA     => ( $openssl, 'ca',  $OPENSSL_CONFIG );
const our @VERIFY => ( $openssl, 'verify' );
const our @X509   => ( $openssl, 'x509' );
const our @PKCS12 => ( $openssl, 'pkcs12' );

# Default values for various configuration settings.
const our $CATOP      => '/etc/ssl';
const our $CAKEY      => 'cakey.pem';
const our $CAREQ      => 'careq.pem';
const our $CACERT     => 'cacert.pem';
const our $CACRL      => 'crl.pem';
const our @DAYS       => qw'-days 365';
const our @CADAYS     => qw'-days 1095';                # 3 years
const our @EXTENSIONS => qw'-extensions v3_ca';
const our @POLICY     => qw'-policy policy_anything';
const our $NEWKEY     => 'newkey.pem';
const our $NEWREQ     => 'newreq.pem';
const our $NEWCERT    => 'newcert.pem';
const our $NEWP12     => 'newcert.p12';

field $ret = 0;
field %extra;
field $what;
field @argv;

method $parse_extra {
    %extra = map { $_ => '' } @OPENSSL_CMDS;

    my @result;

    while ( scalar(@argv) > 0 ) {
        my $arg = shift;

        if ( $arg !~ m/-extra-([a-z0-9]+)/ ) {
            push @result, $arg;
            next;
        }

        $arg =~ s/-extra-//;

        die "Unknown \"-$arg-extra\" option, exiting"
          unless scalar grep { $arg eq $_ } @OPENSSL_CMDS;

        $extra{$arg} .= " " . shift;
    }

    @argv = (@result);
}

# See if reason for a CRL entry is valid; exit if not.
method crl_reason_ok : common ($r) {
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

    say STDERR "Invalid CRL reason; must be one of:";
    say STDERR "  unspecified, keyCompromise, CACompromise";
    say STDERR "  affiliationChanged, superseded, cessationOfOperation";
    say STDERR "  certificateHold, removeFromCRL";

    exit 1;
}

# Copy a PEM-format file; return like exit status (zero means ok)
method copy_pemfile : common ($infile, $outfile, $bound) {
    my $found = 0;

    open my $infh,  '<', $infile  || die "Cannot open '$infile'",      $!;
    open my $outfh, '>', $outfile || die "Cannot write to '$outfile'", $!;

    while ($infh) {
        $found = 1      if /^-----BEGIN.*$bound/;
        print $outfh $_ if $found;
        $found = 2, last if /^-----END.*$bound/;
    }

    close $infh;
    close $outfh;

    $found == 2 ? 0 : 1;
}

# Wrapper around system; useful for debugging.  Returns just the exit status
method sys : common ($cmd, %opt) {
    say "====\n" . join ' ', @$cmd if $opt{verbose} // $verbose;

    my ( @stdout, $stderr );
    my $run3success = run3( $cmd, \undef, \@stdout, \$stderr );
    my $status      = $?;

    say "==> $status\n====" if $opt{verbose} // $verbose;

    $status >> 8;
}

method $run {
    $ENV{DEBUG} && warn Dumper( [ caller 0 ] );
    if ( $what =~ /^(-\?|-h|-help)$/ ) {
        print STDERR <<EOF;
Usage:
CA.pl -newcert | -newreq | -newreq-nodes | -xsign | -sign | -signCA | -signcert | -crl | -newca [-extra-cmd parameter ...]
CA.pl -pkcs12 [certname]
CA.pl -verify certfile ...
CA.pl -revoke certfile [reason]
EOF

        return 0;
    }

    if ( $what eq '-newcert' ) {

        # create a certificate
        $ret = App::OpenSSL::CA->sys(
            [
                @REQ,    '-new', '-x509',  '-keyout',
                $NEWKEY, '-out', $NEWCERT, @DAYS,
                $extra{req}
            ]
        );

        say "Cert is in $NEWCERT, private key is in $NEWKEY"
          if $ret == 0;
    }
    elsif ( $what eq '-precert' ) {

        # create a pre-certificate
        $ret = App::OpenSSL::CA->sys(
            [
                @REQ,    '-x509', '-precert', '-keyout',
                $NEWKEY, '-out',  $NEWCERT,   @DAYS,
                $extra{req}
            ]
        );

        say "Pre-cert is in $NEWCERT, private key is in $NEWKEY" if $ret == 0;
    }
    elsif ( $what =~ /^\-newreq(\-nodes)?$/ ) {

        # create a certificate request
        $ret = App::OpenSSL::CA->sys(
            [
                @REQ,    '-new', $1,      '-keyout',
                $NEWKEY, '-out', $NEWREQ, @DAYS,
                $extra{req}
            ]
        );

        say "Request is in $NEWREQ, private key is in $NEWKEY" if $ret == 0;
    }
    elsif ( $what eq '-newca' ) {

        # create the directory hierarchy
        state @dirs =
          ( $CATOP, map { "$CATOP/$_" } qw(certs crl newcerts private) );

        if (
            my ($fileexists) =
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

        open my $out, ':encoding(UTF-8)>', "$CATOP/index.txt";
        close $out;
        open $out, ':encoding(UTF-8)>', ">$CATOP/crlnumber";
        say $out "01";
        close $out;

        # ask user for existing CA certificate
        say "CA certificate filename (or enter to create)";

        my $FILE;
        $FILE = "" unless defined( $FILE = <STDIN> );

        $FILE =~ s{\R$}{};

        if ( $FILE ne "" ) {
            copy_pemfile( $FILE, "$CATOP/private/$CAKEY", 'PRIVATE' );
            copy_pemfile( $FILE, "$CATOP/$CACERT",        'CERTIFICATE' );
        }
        else {
            say 'Making CA certificate ...';

            $ret = App::OpenSSL::CA->sys(
                [
                    @REQ,      '-new',
                    '-keyout', "$CATOP/private/$CAKEY",
                    '-out',    "$CATOP/$CAREQ",
                    $extra{req}
                ]
            );

            $ret = App::OpenSSL::CA->sys(
                [
                    @CA,         '-create_serial',
                    '-out',      "$CATOP/$CACERT",
                    @CADAYS,     '-batch',
                    '-keyfile',  "$CATOP/private/$CAKEY",
                    '-selfsign', @EXTENSIONS,
                    '-infiles',  "$CATOP/$CAREQ",
                    $extra{ca}
                ]
            ) if $ret == 0;

            say "CA certificate is in $CATOP/$CACERT"
              if $ret == 0;
        }
    }
    elsif ( $what eq '-pkcs12' ) {
        my $cname = $argv[0];

        $cname = "My Certificate" unless defined $cname;

        $ret = App::OpenSSL::CA->sys(
            [
                @PKCS12,          '-in',
                $NEWCERT,         '-inkey',
                $NEWKEY,          '-certfile',
                "$CATOP/$CACERT", '-out',
                $NEWP12,          '-export',
                '-name',          "\"$cname\"",
                $extra{pkcs12}
            ]
        );

        say "PKCS #12 file is in $NEWP12" if $ret == 0;
    }
    elsif ( $what eq '-xsign' ) {
        $ret = App::OpenSSL::CA->sys(
            [ @CA, @POLICY, '-infiles', $NEWREQ, $extra{ca} ] );
    }
    elsif ( $what eq '-sign' ) {
        $ret = App::OpenSSL::CA->sys(
            [ @CA, @POLICY, '-out', $NEWCERT, '-infiles', $NEWREQ, $extra{ca} ]
        );

        say "Signed certificate is in $NEWCERT\n" if $ret == 0;
    }
    elsif ( $what eq '-signCA' ) {
        $ret = App::OpenSSL::CA->sys(
            [
                @CA,         @POLICY,    '-out',  $NEWCERT,
                @EXTENSIONS, '-infiles', $NEWREQ, $extra{ca}
            ]
        );

        say "Signed CA certificate is in $NEWCERT" if $ret == 0;
    }
    elsif ( $what eq '-signcert' ) {
        $ret = App::OpenSSL::CA->sys(
            [
                @X509,      '-x509toreq', '-in',  $NEWREQ,
                '-signkey', $NEWREQ,      '-out', 'tmp.pem',
                $extra{x509}
            ]
        );

        $ret = App::OpenSSL::CA->sys(
            [
                @CA,        @POLICY,   '-out', $NEWCERT,
                '-infiles', 'tmp.pem', $extra{ca}
            ]
        ) if $ret == 0;

        say "Signed certificate is in $NEWCERT" if $ret == 0;
    }
    elsif ( $what eq '-verify' ) {
        my @files = @argv ? @argv : ($NEWCERT);

        foreach my $file (@files) {

            # -CAfile quoted for VMS, since the C RTL downcases all unquoted
            # arguments to C programs
            my $status = App::OpenSSL::CA->sys(
                [
                    @VERIFY,          '"-CAfile"',
                    "$CATOP/$CACERT", $file,
                    $extra{verify}
                ]
            );

            $ret = $status if $status != 0;
        }
    }
    elsif ( $what eq '-crl' ) {
        $ret = App::OpenSSL::CA->sys(
            [ @CA, '-gencrl', '-out', "$CATOP/crl/$CACRL", $extra{ca} ] );
    }
    elsif ( $what eq '-revoke' ) {
        my $cname  = $ARGV[0];
        my @reason = $ARGV[1];
        unshift @reason, '-crl_reason';

        $ret = App::OpenSSL::CA->sys(
            [ @CA, '-revoke', "'$cname'", @reason, $extra{ca} ] )
          if scalar @reason == 2 && __PACKAGE__->crl_reason_okay( $reason[1] );
    }
    else {
        say STDERR "Unknown arg \"$what\"";
        say STDERR "Use -help for help.";
        return 1;
    }

    $ret;
}

method $setup (@_argv) {
    @argv = (@_argv);
    $what = shift @argv || '';
    $self->$parse_extra;
}

method cmd(@argv) {
    $setup->( $self, @argv );
    $self->$run();
}

method run : common (@argv) {
    $class->new->cmd(@argv);
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
