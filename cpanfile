use utf8;
use v5.40;

requires 'perl', 'v5.40';

requires 'Const::Fast';
requires 'Object::Pad';
requires 'List::Util';

on 'test' => sub {
  requires 'Test::More', '0.98';
};
