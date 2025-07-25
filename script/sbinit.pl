#!/usr/bin/env perl

use Object::Pad ':experimental(:all)';

package SecureBootInit;

class SecureBootInit;

use utf8;
use v5.42;

use Data::Dumper;
use IPC::Run3;
use Getopt::Long;
use Pod::Usage;
use Time::HiRes qw(gettimeofday);
use Net::SSLeay;

#field $cliopts :param;
field $argv : param;

field $cn : param;
field $o : param  = undef;
field $ou : param = undef;
field $subj_base //= "/CN=$cn/";

ADJUSTPARAMS($params) {
    GetOptionsFromArray(
        $argv,
        "organization=s"                  => $o,
        "ou|organization-unit|org-unit=s" => $ou,
        "cn|common-name=s"                => $cn,
        "subj|subject=s"                  => $subj_base
    );

    if ( my (%subj) = ( $subj =~ $SUBJ_PTN ) ) {
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

method make_anonymous : common ( $salt = __CLASS__->epoch ) {
    my $string = `hostname`;
    $string .= ",$salt";

    my $secret = Net::SSLeay::SHA511( Net::SSLeay::gen_random(32) );

    srand unpack "N", hide_data( $string, 3, "silly" );

    cfg_expand(
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

method epoch : common ($join = '') {
    join $join, gettimeofday;
}

