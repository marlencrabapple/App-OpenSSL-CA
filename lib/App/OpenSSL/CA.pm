use Object::Pad qw(:experimental(:all));

package App::OpenSSL::CA;
class App::OpenSSL::CA 0.01;

use utf8;
use v5.40;

use Const::Fast;
use List::Util 'any';

our $VERSION = "0.01";

const our $verbose => $ENV{VERBOSE} // 1;
const our @OPENSSL_CMDS => qw'req ca pkcs12 x509 verify';

const our $openssl => $ENV{OPENSSL} = $ENV{OPENSSL} // 'openssl';
const our $OPENSSL_CONFIG => $ENV{OPENSSL_CONFIG} // '';

# Command invocations.
const our @REQ => ($openssl, 'req', $OPENSSL_CONFIG);
const our @CA => ($openssl, 'ca', $OPENSSL_CONFIG);
const our @VERIFY => ($openssl, 'verify');
const our @X509 => ($openssl, 'x509');
const our @PKCS12 => ($openssl, 'pkcs12');

# Default values for various configuration settings.
const our $CATOP => '/etc/ssl';
const our $CAKEY => 'cakey.pem';
const our $CAREQ => 'careq.pem';
const our $CACERT => 'cacert.pem';
const our $CACRL => 'crl.pem';
const our @DAYS => qw'-days 365';
const our @CADAYS => qw'-days 1095';	# 3 years
const our @EXTENSIONS => qw'-extensions v3_ca';
const our @POLICY => qw'-policy policy_anything';
const our $NEWKEY => 'newkey.pem';
const our $NEWREQ => 'newreq.pem';
const our $NEWCERT => 'newcert.pem';
const our $NEWP12 => 'newcert.p12';

field $RET = 0;
field %EXTRA;
field $WHAT;
field @argv;

method $parse_extra {
  %EXTRA = map { $_ => '' } @OPENSSL_CMDS;

  my @result;

  while (scalar(@argv) > 0) {
    my $arg = shift;
    
    if ($arg !~ m/-extra-([a-z0-9]+)/) {
      push @result, $arg;
      next
    }

    $arg =~ s/-extra-//;

    die "Unknown \"-$arg-extra\" option, exiting"
      unless scalar grep { $arg eq $_ } @OPENSSL_CMDS;

    $EXTRA{$arg} .= " " . shift
  }

  @argv = (@result)
}

# See if reason for a CRL entry is valid; exit if not.
method crl_reason_ok :common ($r) {
  if ($r eq 'unspecified' || $r eq 'keyCompromise'
      || $r eq 'CACompromise' || $r eq 'affiliationChanged'
      || $r eq 'superseded' || $r eq 'cessationOfOperation'
      || $r eq 'certificateHold' || $r eq 'removeFromCRL') {
    return 1
  }

  say STDERR "Invalid CRL reason; must be one of:";
  say STDERR "  unspecified, keyCompromise, CACompromise";
  say STDERR "  affiliationChanged, superseded, cessationOfOperation";
  say STDERR "  certificateHold, removeFromCRL";

  exit 1
}

# Copy a PEM-format file; return like exit status (zero means ok)
method copy_pemfile :common ($infile, $outfile, $bound) {
  my $found = 0;

  open my $infh, $infile || die "Cannot open $infile, $!";
  open my $outfh, ">$outfile" || die "Cannot write to $outfile, $!";

  while ($infh) {
    $found = 1 if /^-----BEGIN.*$bound/;
    print $outfh $_ if $found;
    $found = 2, last if /^-----END.*$bound/;
  }

  close $infh;
  close $outfh;

  $found == 2 ? 0 : 1
}

# Wrapper around system; useful for debugging.  Returns just the exit status
method sys :common ($cmd, %opt) {
  say "====\n$cmd" if $opt{verbose} // $verbose;
  my $status = system(@$cmd);
  say "==> $status\n====" if $opt{verbose} // $verbose;

  $status >> 8
}

method $run {
  if ($WHAT =~ /^(-\?|-h|-help)$/) {
    print STDERR <<EOF;
Usage:
CA.pl -newcert | -newreq | -newreq-nodes | -xsign | -sign | -signCA | -signcert | -crl | -newca [-extra-cmd parameter]
CA.pl -pkcs12 [certname]
CA.pl -verify certfile ...
CA.pl -revoke certfile [reason]
EOF

    return 0
  }

  if ($WHAT eq '-newcert') {
    # create a certificate
    $RET = run([@REQ, '-new', '-x509', '-keyout', $NEWKEY, '-out', $NEWCERT
      , @DAYS, $EXTRA{req}]);

    say "Cert is in $NEWCERT, private key is in $NEWKEY"
      if $RET == 0
  }
  elsif ($WHAT eq '-precert') {
    # create a pre-certificate
    $RET = run([@REQ, '-x509', '-precert', '-keyout', $NEWKEY, '-out', $NEWCERT
      , @DAYS, $EXTRA{req}]);

    say "Pre-cert is in $NEWCERT, private key is in $NEWKEY" if $RET == 0
  }
  elsif ($WHAT =~ /^\-newreq(\-nodes)?$/) {
    # create a certificate request
    $RET = run([@REQ, '-new', $1, '-keyout', $NEWKEY, '-out', $NEWREQ, @DAYS
      , $EXTRA{req}]);

    say "Request is in $NEWREQ, private key is in $NEWKEY" if $RET == 0;
  }
  elsif ($WHAT eq '-newca') {
    # create the directory hierarchy
    state @dirs = ($CATOP, map { "$CATOP/$_" } qw(certs crl newcerts private));

    die "$_ exists.\nRemove old sub-tree to proceed,"
      if any { -f "$CATOP/$_" } qw(index.txt serial);

    foreach my $d (@dirs) {
      -d $d
        ? warn "Directory $d exists"
        : mkdir $d or die "Can't mkdir $d, $!"
    }

    open my $out, ">$CATOP/index.txt";
    close $out;
    open $out, ">$CATOP/crlnumber";
    say $out "01";
    close $out;

    # ask user for existing CA certificate
    say "CA certificate filename (or enter to create)";

    my $FILE;
    $FILE = "" unless defined($FILE = <STDIN>);

    $FILE =~ s{\R$}{};

    if ($FILE ne "") {
      copy_pemfile($FILE, "$CATOP/private/$CAKEY", 'PRIVATE');
      copy_pemfile($FILE, "$CATOP/$CACERT", 'CERTIFICATE')
    }
    else {
      say 'Making CA certificate ...';

      $RET = sys([@REQ, '-new', '-keyout', "$CATOP/private/$CAKEY", '-out'
        , "$CATOP/$CAREQ", $EXTRA{req}]);
      
      $RET = sys([@CA, '-create_serial', '-out', "$CATOP/$CACERT", @CADAYS
        , '-batch', '-keyfile', "$CATOP/private/$CAKEY", '-selfsign'
        , @EXTENSIONS, '-infiles', "$CATOP/$CAREQ", $EXTRA{ca}])
          if $RET == 0;
      
      say "CA certificate is in $CATOP/$CACERT"
        if $RET == 0
    }
  }
  elsif ($WHAT eq '-pkcs12') {
    my $cname = $argv[0];

    $cname = "My Certificate" unless defined $cname;

    $RET = sys([@PKCS12, '-in', $NEWCERT, '-inkey', $NEWKEY, '-certfile'
      , "$CATOP/$CACERT", '-out', $NEWP12, '-export', '-name', "\"$cname\""
      , $EXTRA{pkcs12}]);

    say "PKCS #12 file is in $NEWP12" if $RET == 0
  }
  elsif ($WHAT eq '-xsign') {
    $RET = sys([@CA, @POLICY, '-infiles', $NEWREQ, $EXTRA{ca}])
  }
  elsif ($WHAT eq '-sign') {
    $RET = sys([@CA, @POLICY, '-out', $NEWCERT, '-infiles', $NEWREQ
      , $EXTRA{ca}]);

    say "Signed certificate is in $NEWCERT\n" if $RET == 0
  }
  elsif ($WHAT eq '-signCA') {
    $RET = sys([@CA, @POLICY, '-out', $NEWCERT, @EXTENSIONS, '-infiles', $NEWREQ
      , $EXTRA{ca}]);

    say "Signed CA certificate is in $NEWCERT" if $RET == 0
  }
  elsif ($WHAT eq '-signcert') {
    $RET = sys([@X509, '-x509toreq', '-in', $NEWREQ, '-signkey', $NEWREQ, '-out'
      , 'tmp.pem', $EXTRA{x509}]);

    $RET = sys([@CA, @POLICY, '-out', $NEWCERT, '-infiles', 'tmp.pem'
      , $EXTRA{ca}])
        if $RET == 0;

    say "Signed certificate is in $NEWCERT" if $RET == 0
  }
  elsif ($WHAT eq '-verify') {
    my @files = @argv ? @argv : ($NEWCERT);

    foreach my $file (@files) {
      # -CAfile quoted for VMS, since the C RTL downcases all unquoted
      # arguments to C programs
      my $status = run([@VERIFY, '"-CAfile"', "$CATOP/$CACERT", $file
        , $EXTRA{verify}]);
      
      $RET = $status if $status != 0
    }
  }
  elsif ($WHAT eq '-crl') {
    $RET = sys([@CA, '-gencrl', '-out', "$CATOP/crl/$CACRL", $EXTRA{ca}]);
    say "Generated CRL is in $CATOP/crl/$CACRL" if $RET == 0
  }
  elsif ($WHAT eq '-revoke') {
    my $cname = $argv[0];

    if (!defined $cname) {
      say "Certificate filename is required; reason optional.";
      return 1
    }

    my @reason = ($argv[1]);

    unshift @reason, '-crl_reason'
      if defined $reason[0] && crl_reason_ok(@reason);

    $RET = sys([@CA, '-revoke', '"$cname"', @reason, $EXTRA{ca}])
  }
  else {
    say STDERR "Unknown arg \"$WHAT\"";
    say STDERR "Use -help for help.";
    return 1
  }

  $RET
}

method $setup (@_argv) {
  @argv = (@_argv);
  $WHAT = shift @argv || '';
  $self->$parse_extra;
}

method cmd (@argv) {
  $self->$setup->(@argv);
  $self->$run->()
}

method run :common (@argv) {
  $class->new->cmd(@argv)
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

