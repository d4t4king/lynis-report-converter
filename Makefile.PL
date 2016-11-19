use 5.010001;

use strict;
use warnings;

use ExtUtils::MakeMaker;

my ($mm) = $ExtUtils::MakeMaker::VERSION =~ /^([^_]+)/;

WriteMakefile(
	NAME			=>	'lynis-report-converter',
	VERSION_FROM	=>	'lynis-report-converter.pl',
	ABSTRACT		=>	'Because lynis needs a transportable report sometimes.',
	AUTHOR			=>	'Charlie Heselton <dataking@gmail.com>',

	($mm < 6.3002 ? () : ('LICENSE' => 'artistic_2')),

	PREREQ_PM		=>	{
		'HTML::HTMLDoc'			=>	0,
		'Excel::Writer::XLSX'	=>	0,
	},
);
