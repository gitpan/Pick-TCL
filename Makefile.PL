use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Pick::TCL',
    AUTHOR              => q{Jack Burton <jack@saosce.com.au>},
    VERSION_FROM        => 'lib/Pick/TCL.pm',
    ABSTRACT_FROM       => 'lib/Pick/TCL.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    META_MERGE => {
        optional_features => {
            local_pick => {
                description => "Connect to a local Pick VM without ssh",
                requires => { 'IPC::Run' => 0, },
            },
            remote_pick => {
                description => "Connect to a Pick VM over ssh",
                requires => { 'Net::OpenSSH' => 0, },
            },
        },
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Pick-TCL-*' },
);
