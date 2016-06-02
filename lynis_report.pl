#!/usr/bin/perl -w

use strict;
use warnings;

use Term::ANSIColor;
use Getopt::Long qw( :config no_ignore_case bundling );
use Data::Dumper;

my ($help,$verbose,$excel);
GetOptions(
	'h|help'		=>	\$help,
	'v|verbose+'	=>	\$verbose,
	'E|excel'		=>	\$excel,
);

my $lynis_log = '/var/log/lynis.log';
my $lynis_report = '/var/log/lynis-report.dat';
my $audit_run = 0;									#assume false
if ( -e $lynis_log and ! -z $lynis_log ) {
	print colored("Found lynis output log. \n", "cyan") if ($verbose);
	$audit_run++;
}
if ( -e $lynis_report and ! -z $lynis_report ) {
	print colored("Found lynis report. \n", "cyan") if ($verbose);
	$audit_run++;
}

if ($audit_run) and ($audit_run >= 1) {
	print "Looks like the audit has been run. \n";
} else {
	print colored("Couldn't find one or more of the lynis output files.  Try running the audit again. \n", "bold red");
}
