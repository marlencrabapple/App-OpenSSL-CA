#!/usr/bin/env perl

use utf8;
use v5.40;

use App::OpenSSL::CA;

our $RET = 0;
$RET = App::OpenSSL::CA->do( \@ARGV );

exit $RET

