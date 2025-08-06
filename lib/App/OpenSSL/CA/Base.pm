use Object::Pad ':experimental(:all)';

package App::OpenSSL::CA::Base;
role App::OpenSSL::CA::Base;

use utf8;
use v5.40;

use Const::Fast::Exporter;
use Data::Dumper;
use Time::HiRes ();
use Time::Piece;
use Time::Moment;
use Syntax::Keyword::Dynamically;
use Syntax::Keyword::MultiSub;

use Exporter 'import';

use subs qw(dmsg epoch err);

BEGIN {
    use Exporter 'import';
    our @EXPORT = qw(dmsg epoch err);
}

const our $DEBUG        => $ENV{DEBUG} // 0;
const our $S_UNKNOWNERR => 'Unknown fatal error';

eval "use Devel::StackTrace::WithLexicals" if $DEBUG;

field $debug = $DEBUG;

APPLY {
    #__PACKAGE__->dmsg( { INC => \@INC } );

    use utf8;
    use v5.40;

    use Exporter 'import';

    our @EXPORT = @{__PACKAGE__::EXPORT}
};

ADJUSTPARAMS($param) {

    # ...
}

multi sub epoch( $class = undef, $join = '', $eol = "\n" ) {
    join $join, Time::HiRes::gettimeofday;
}

multi sub epoch( $class = undef, $fmtstr = '', $eol = "\n" ) {
    sprintf( "$fmtstr$eol" // "%d%d$eol", Time::HiRes::gettimeofday );
}

# Use Syntax::Keyword::MultiSub or prototypes if checking the caller isn't convenient,
sub dmsg ( $class = undef, @msgs ) {
    $DEBUG || return '';

    my @caller = caller 0;

    my $out = "*** " . localtime->datetime . " - DEBUG MESSAGE ***\n\n";

    dynamically $Data::Dumper::Pad    = "  ";
    dynamically $Data::Dumper::Indent = 1;

    $out .=
        scalar @msgs > 1 ? Dumper(@msgs)
      : ref $msgs[0]     ? Dumper(@msgs)
      :                    eval { my $s = $msgs[0] // 'undef'; "  $s\n" };

    $out .= "\n";

    $out .=
      $ENV{DEBUG} && $ENV{DEBUG} == 2
      ? join "\n", map { ( my $line = $_ ) =~ s/^\t/  /; "  $line" } split /\R/,
      Devel::StackTrace::WithLexicals->new(
        indent      => 1,
        skip_frames => 1
      )->as_string
      : "at $caller[1]:$caller[2]";

    say STDERR "$out\n";
    $out;
}

sub err : prototype($$%) (
    $msg_aref = ( [ $! // $S_UNKNOWNERR ] ),
    $exit     = ( $? ? $? >> 8 : 255 ), %opts
  )
{
    dmsg( { exit => $exit, msg_aref => $msg_aref, opts => \%opts } );

    my $errstr = join "\n", map {
        my $str = $_ isa 'HASH' ? $$_{msg} : $_;
        $str = $S_UNKNOWNERR if $str =~ /^[0-9]+$/ && $str == 0;
        $str
    } @$msg_aref;

    die "ERROR: $errstr ($exit)";
}

method help : common ( $error = "", $exit = ($? >> 8 || 0)) {
    my $caller = [ caller 0 ];

    warn "$error $$caller[0]:$$caller[1] line " . __LINE__ . "\n\n" if $error;

    $class->dmsg( { caller => $caller, ( $error ? ( error => $error ) : () ) } )
      if $DEBUG > 1;

    warn <<EOF;
Usage:
    CA.pl -newcert | -newreq | -newreq-nodes | -xsign | -sign | -signCA | -signcert | -crl | -newca [-extra-cmd parameter]
    CA.pl -pkcs12 [certname]
    CA.pl -verify certfile ...
    CA.pl -revoke certfile [reason]
EOF
    exit $exit;
}
