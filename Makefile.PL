use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'TagFilter',
    'VERSION_FROM'	=> 'TagFilter.pm', # finds $VERSION
    'PREREQ_PM'		=> {HTML::Parser}, # e.g., Module::Name => 1.1
);
