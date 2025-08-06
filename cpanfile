requires 'perl', 'v5.40';

requires 'Path::Tiny';
requires 'Const::Fast';
requires 'Object::Pad';
requires 'List::Util';
requires 'Net::SSLeay';
requires 'IPC::Run3';
requires 'Syntax::Keyword::Dynamically';
requires 'Syntax::Keyword::Defer';
requires 'Devel::StackTrace::WithLexicals';
requires 'Time::Piece';
requires 'Time::Moment';
requires 'Const::Fast::Exporter';

on 'test' => sub {
    requires 'Module::Build::Tiny';
    requires 'Test::More', '0.98';
};
