use Object::Pad ':experimental(:all)';

package App::OpenSSL::CA::Util;
role App::OpenSSL::CA::Util : does(App::OpenSSL::CA::Base);

use utf8;
use v5.40;

use Syntax::Keyword::Dynamically;

#use App::OpenSSL::CA::Util;
sub rc4 : prototype($$;$) ( $message, $key, $skip = undef ) {
    my @s       = 0 .. 255;
    my @k       = unpack 'C*', $key;
    my @message = unpack 'C*', $message;

    #my ( $x, $y );
    $skip = 256 unless ( defined $skip );

    my $y = 0;

    for my $x ( 0 .. 255 ) {
        $y = ( $y + $s[$x] + $k[ $x % @k ] ) % 256;
        @s[ $x, $y ] = @s[ $y, $x ];
    }

    my $x = 0;
    $y = 0;

    for my $i ( 1 .. $skip ) {
        $x = ( $x + 1 ) % 256;
        $y = ( $y + $s[$x] ) % 256;
        @s[ $x, $y ] = @s[ $y, $x ];
    }

    for my $msg (@message) {
        $x = ( $x + 1 ) % 256;
        $y = ( $y + $s[$x] ) % 256;
        @s[ $x, $y ] = @s[ $y, $x ];
        $msg ^= $s[ ( $s[$x] + $s[$y] ) % 256 ];
    }

    pack 'C*', @message;
}

sub hide_data : prototype($$$$;$)
  ( $data, $bytes, $key, $secret, $base64 = undef ) {
    my $crypt =
      rc4( null_string($bytes), make_key( $key, $secret, 32 ) . $data );

    return encode_base64( $crypt, "" ) if $base64;
    return $crypt;
}

method cfg_expand : common : prototype($%) ( $str, %grammar ) {
    my $expanded = $str =~ s/%(\w+)%/
		  my @expansions=@{$grammar{$1}};
		  $class->cfg_expand($expansions[rand @expansions],%grammar);
	  /rxge;

    $expanded;
}

method make_anonymous : common ( $salt = __CLASS__->epoch ) {
    my $string = `hostname`;
    $string .= ",$salt";

    srand unpack "N",
      hide_data( $string, 3, "silly",
        Net::SSLeay::SHA512( Net::SSLeay::gen_random(32) ) );

    $class->cfg_expand(
        "%G% %W%",
        W => [
            "%B%%V%%M%%I%%V%%F%", "%B%%V%%M%%E%",
            "%O%%E%",             "%B%%V%%M%%I%%V%%F%",
            "%B%%V%%M%%E%",       "%O%%E%",
            "%B%%V%%M%%I%%V%%F%", "%B%%V%%M%%E%"
        ],
        B => [
            "B",  "B",  "C",  "D",  "D", "F", "F", "G", "G",  "H",
            "H",  "M",  "N",  "P",  "P", "S", "S", "W", "Ch", "Br",
            "Cr", "Dr", "Bl", "Cl", "S"
        ],
        I => [
            "b", "d", "f", "h", "k",  "l", "m", "n",
            "p", "s", "t", "w", "ch", "st"
        ],
        V => [ "a", "e", "i", "o", "u" ],
        M => [
            "ving",  "zzle",  "ndle",  "ddle",  "ller", "rring",
            "tting", "nning", "ssle",  "mmer",  "bber", "bble",
            "nger",  "nner",  "sh",    "ffing", "nder", "pper",
            "mmle",  "lly",   "bling", "nkin",  "dge",  "ckle",
            "ggle",  "mble",  "ckle",  "rry"
        ],
        F => [
            "t",  "ck",  "tch", "d",   "g",   "n",
            "t",  "t",   "ck",  "tch", "dge", "re",
            "rk", "dge", "re",  "ne",  "dging"
        ],
        O => [
            "Small",    "Snod",   "Bard",    "Billing",
            "Black",    "Shake",  "Tilling", "Good",
            "Worthing", "Blythe", "Green",   "Duck",
            "Pitt",     "Grand",  "Brook",   "Blather",
            "Bun",      "Buzz",   "Clay",    "Fan",
            "Dart",     "Grim",   "Honey",   "Light",
            "Murd",     "Nickle", "Pick",    "Pock",
            "Trot",     "Toot",   "Turvey"
        ],
        E => [
            "shaw",  "man",   "stone", "son",   "ham",   "gold",
            "banks", "foot",  "worth", "way",   "hall",  "dock",
            "ford",  "well",  "bury",  "stock", "field", "lock",
            "dale",  "water", "hood",  "ridge", "ville", "spear",
            "forth", "will"
        ],
        G => [
            "Albert",    "Alice",     "Angus",     "Archie",
            "Augustus",  "Barnaby",   "Basil",     "Beatrice",
            "Betsy",     "Caroline",  "Cedric",    "Charles",
            "Charlotte", "Clara",     "Cornelius", "Cyril",
            "David",     "Doris",     "Ebenezer",  "Edward",
            "Edwin",     "Eliza",     "Emma",      "Ernest",
            "Esther",    "Eugene",    "Fanny",     "Frederick",
            "George",    "Graham",    "Hamilton",  "Hannah",
            "Hedda",     "Henry",     "Hugh",      "Ian",
            "Isabella",  "Jack",      "James",     "Jarvis",
            "Jenny",     "John",      "Lillian",   "Lydia",
            "Martha",    "Martin",    "Matilda",   "Molly",
            "Nathaniel", "Nell",      "Nicholas",  "Nigel",
            "Oliver",    "Phineas",   "Phoebe",    "Phyllis",
            "Polly",     "Priscilla", "Rebecca",   "Reuben",
            "Samuel",    "Sidney",    "Simon",     "Sophie",
            "Thomas",    "Walter",    "Wesley",    "William"
        ],
    );
}
