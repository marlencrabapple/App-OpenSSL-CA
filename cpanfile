use utf8;
use v5.40;

requires 'perl', 'v5.40';

requires 'Path::Tiny';
requires 'Const::Fast';
requires 'Object::Pad';
requires 'List::Util';
requires 'Net::SSLeay';
requires 'IPC::Run3';
requires 'Syntax::Keyword::Dynamically';
requires 'Syntax::Keyword::Defer';

#requires '$yntax::Keyword::'

on 'test' => sub {
    requires 'Test::More', '0.98';
};
