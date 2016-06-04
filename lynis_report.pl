#!/usr/bin/perl -w

use strict;
use warnings;
use feature qw( switch );
no warnings "experimental::smartmatch";
use Term::ANSIColor;
use Getopt::Long qw( :config no_ignore_case bundling );
use Data::Dumper;

my ($help,$verbose,$excel,$output);
GetOptions(
	'h|help'		=>	\$help,
	'v|verbose+'	=>	\$verbose,
	'E|excel'		=>	\$excel,
	'o|output=s'	=>	\$output,
);

my %to_bool = (	0 => 'false', 1 => 'true' );
my %to_long_severity = ( 'C' => 'Critical', 'S' => 'Severe', 'H' => 'High', 'M' => 'Medium', 'L' => 'Low', 'I' => 'Informational' );

$output = "report.html" unless ((defined($output)) and ($output ne ""));

my $lynis_log = '/var/log/lynis.log';
my $lynis_report = '/var/log/lynis-report.dat';
my $audit_run = 0;									#assume false
my %lynis_report_data;

if (( -e $lynis_log) and ( ! -z $lynis_log )) {
	print colored("Found lynis output log. \n", "cyan") if ($verbose);
	$audit_run++;
}
if (( -e $lynis_report) and ( ! -z $lynis_report )) {
	print colored("Found lynis report. \n", "cyan") if ($verbose);
	$audit_run++;
}

if (($audit_run) and ($audit_run >= 1)) {
	print "Looks like the audit has been run. \n";
} else {
	print colored("Couldn't find one or more of the lynis output files.  Try running the audit again. \n", "bold red");
}

print "Outputting report to $output, in ";
if ($excel) { print "Excel " }
else { print "HTML "; }
print "format. \n";

# the report is easy to process, and actually doesn't contain the "audit findings"....just the data.
# but it is not our job to draw conclusions here, just present the findings of the tool.
open RPT, "<$lynis_report" or die colored("There was a problem opening the lynis report: $! \n", "bold red");
while (my $line = <RPT>) {
	next if ($line =~ /^#/);			# skip commented lines
	chomp($line);
	my ($k, $v) = split(/=/, $line);
	print "k=$k\n" if (($verbose) and ($verbose > 1));
	print "v=$v\n" if (($verbose) and ($verbose > 1));
	# if the key already exists, assume it's supposed to be an array value.  Array values are handled a couple
	# different ways in the lynis report.  This is just one.
	if (exists($lynis_report_data{$k})) {
		if (ref($lynis_report_data{$k}) eq 'ARRAY') {
			push @{$lynis_report_data{$k}}, $v;
		} else {
			my $tmp_v = $lynis_report_data{$k};
			undef($lynis_report_data{$k});
			push @{$lynis_report_data{$k}}, $tmp_v, $v;
		}
	} else {
		$lynis_report_data{$k} = $v;
	}
}
close RPT or die colored("There was a problem closing the lynis report: $! \n", "bold red");

my (%warnings, %suggestions);
#foreach my $warn ( sort @{$lynis_report_data{'warning[]'}} ) {
#	my ($warn_id,$descr, $sev, $field4) = split(/\|/, $warn);
#	$warnings{$warn_id}{'id'} = $warn_id;
#	$warnings{$warn_id}{'descr'} = $descr;
#	$warnings{$warn_id}{'severity'} = $sev;
#	$warnings{$warn_id}{'f4'} = $field4;
#}
#delete($lynis_report_data{'warning[]'});

# process "string array" values delimited by a pipe (|)
foreach my $key ( sort keys %lynis_report_data ) {
	print "$key, ".ref($lynis_report_data{$key})." \n" if (($verbose) and ($verbose >= 1));
	if (((ref($lynis_report_data{$key}) ne 'ARRAY') and
		(ref($lynis_report_data{$key}) ne 'HASH')) and
		($lynis_report_data{$key} =~ /\|/)) {
		my @fs = split(/\|/, $lynis_report_data{$key});
		undef($lynis_report_data{$key});
		push @{$lynis_report_data{$key}}, @fs;
	}
}

my (@tests_skipped, @tests_executed);
my ($lynis_version);

@tests_skipped = @{$lynis_report_data{'tests_skipped'}};
delete($lynis_report_data{'tests_skipped'});
@tests_executed = @{$lynis_report_data{'tests_executed'}};
delete($lynis_report_data{'tests_executed'});

#print Dumper(\%warnings);

open OUT, ">$output" or die colored("There was a problem opening the output file ($output): $! \n", "bold red");
print OUT <<END;

<html >
	<head>
		<meta >
		<style>
			html,body {color: #fff; background-color: #000;}
			table {border-collapse: collapse; border: 1px solid white;}
			td.good {background-color: #006400; color: #ffffff; font-weight: bold;}
			td.fair {background-color: #ffd700; color: #000000; font-weight: bold;}
			td.poor {background-color: #ffa500; color: #000000; font-weight: bold;}
			td.dismal {background-color: #ff00000; color: #000000; font-weight: bold;}
			span.title_shrink {font-size: 75%;}
		</style>
	</head>
	<body>
		<h1>lynis Asset Report</h1>
		<h2><span class="title_shrink">created by</span> lynis_report</h2>
		<hr>
		<h4>lynis info:</h4>
		<table border="1">
			<tr>
				<td>lynis version:</td><td>$lynis_report_data{'lynis_version'}</td><td>lynis tests done:</td><td>$lynis_report_data{'lynis_tests_done'}</td>
			</tr>
			<tr>
				<td>lynis update available:</td><td>$to_bool{$lynis_report_data{'lynis_update_available'}}</td><td>license key:</td><td>$lynis_report_data{'license_key'}</td>
			</tr>
			<tr>
				<td colspan="2">report version:</td><td colspan="2">$lynis_report_data{'report_version_major'}.$lynis_report_data{'report_version_minor'}</td>
			</tr>
			<tr>
				<td>number of plugins enabled:</td><td>$lynis_report_data{'plugins_enabled'}</td><td>plugin directory:</td><td>$lynis_report_data{'plugin_directory'}</td>
			</tr>
			<tr>
END

print OUT "\t\t\t\t<td>phase 1 plugins enabled:</td><td colspan=\"3\">";
print OUT "\t\t\t\t\t<table border=\"1\">\n";
foreach my $plug ( sort @{$lynis_report_data{'plugin_enabled_phase1[]'}} ) { 
	my ($n,$v) = split(/\|/, $plug);
	print OUT "\t\t\t\t\t\t<tr><td>name:</td><td>$n</td><td>version:</td><td>$v</td></tr>\n";
}
print OUT "\t\t\t\t\t</table>\n";
print OUT "</td>\n";
print OUT <<END;
			</tr>
			<tr>
				<td>report start time:</td><td>$lynis_report_data{'report_datetime_start'}</td><td>report end time:</td><td>$lynis_report_data{'report_datetime_end'}</td>
			</tr>
			<tr><td>hostid:</td><td colspan="3">$lynis_report_data{'hostid'}</td></tr>
			<tr><td>hostid:</td><td colspan="3">$lynis_report_data{'hostid2'}</td></tr>
		</table>
		<h4>host findings:</h4>
		<table border="1"><tr><td>hardening index:</td>
END

given ($lynis_report_data{'hardening_index'}) {
	when (($lynis_report_data{'hardening_index'} < 100) and ($lynis_report_data{'hardening_index'} > 90)) {
		# green
		print OUT "\t\t\t<td class=\"good\">$lynis_report_data{'hardening_index'}</td>";
	}
	when (($lynis_report_data{'hardening_index'} <= 90) and ($lynis_report_data{'hardening_index'} > 80)) {
		# yellow
		print OUT "\t\t\t<td class=\"fair\">$lynis_report_data{'hardening_index'}</td>";
	}
	when (($lynis_report_data{'hardening_index'} <= 80) and ($lynis_report_data{'hardening_index'} > 65)) {
		# orange
		print OUT "\t\t\t<td class=\"poor\">$lynis_report_data{'hardening_index'}</td>";
	}
	when ($lynis_report_data{'hardening_index'} <= 65) {
		# red
		print OUT "\t\t\t<td class=\"dismal\">$lynis_report_data{'hardening_index'}</td>";
	}
	default { 
		# error
	}
}

print OUT "\t\t</tr></table>\n";
print OUT "<h4>warnings (".scalar(@{$lynis_report_data{'warning[]'}})."):</h4>\n";
print OUT <<END;
		<table border="1">
		<tr><td>Warning ID</td><td>Description</td><td>Severity</td><td>F4</td></tr>
END
if (ref($lynis_report_data{'warning[]'}) eq 'ARRAY') {
	if (${$lynis_report_data{'warning[]'}}[0] =~ /\|/) { 									# more than one
		foreach my $warn ( sort @{$lynis_report_data{'warning[]'}} ) {
			my ($warn_id,$warn_desc,$warn_sev,$warn_f4) = split(/\|/, $warn);
			print OUT "<tr><td>$warn_id</td><td>$warn_desc</td><td>$to_long_severity{$warn_sev}</td><td>$warn_f4</td></tr>\n";
		}
	} elsif (${$lynis_report_data{'warning[]'}}[0] =~ /[A-Z]{4}\-\d{4}/) {					# one warning
		my $warn_id = ${$lynis_report_data{'warning[]'}}[0];
		my $warn_desc = ${$lynis_report_data{'warning[]'}}[1];
		my $warn_sev = ${$lynis_report_data{'warning[]'}}[2];
		my $warn_f4 = ${$lynis_report_data{'warning[]'}}[3];
		print OUT "<tr><td>$warn_id</td><td>$warn_desc</td><td>$to_long_severity{$warn_sev}</td><td>$warn_f4</td></tr>\n";
	} else {
		die colored("Unexpected ARRAY format! \n", "bold red");
	}
} else {
	die colored("warning[] not ARRAY ref!: ".ref($lynis_report_data{'warning[]'})."\n", "bold red");
}
print OUT <<END;
		</table>
END
print OUT "\t\t<h4>suggestions (".scalar(@{$lynis_report_data{'suggestion[]'}})."):</h4>\n";
print OUT <<END;
		<table border="1">
			<tr><td>Suggestion ID</td><td>Description</td><td>Severity</td><td>F4</td></tr>
END
if ((ref($lynis_report_data{'suggestion[]'}) eq 'ARRAY') and
	(${$lynis_report_data{'suggestion[]'}}[0] =~ /\|/)) {
	foreach my $sug ( sort @{$lynis_report_data{'suggestion[]'}} ) {
		my ($sug_id,$sug_desc,$sug_sev,$sug_f4,$sug_f5) = split(/\|/, $sug);
		if ($sug_desc eq 'Consider hardening SSH configuration') {
			$sug_desc .= ": $sug_sev"; $sug_sev = '-';
		}
		print OUT "\t\t\t<tr><td>$sug_id</td><td>$sug_desc</td><td>$sug_sev</td><td>$sug_f4</td></tr>\n";
	}
}
print OUT <<END;
		</table>
		<h4>manual checks:</h4>
		<ul>
END
foreach my $man ( sort @{$lynis_report_data{'manual[]'}} ) {
	#print Dumper($man);
	print OUT "<li>$man</li>\n";
}
print OUT <<END;
		</ul>
	</body>
</html>

END

close OUT or die colored("There was a proble closing the output file ($output): $! \n", "bold red");

my @indexes = qw( lynis_version lynis_tests_done lynis_update_available license_key report_datetime_start report_datetime_end plugins_directory plugins_enabled finish report_version_major report_version_minor hostid hostid2 plugin_enabled_phase1[] hardening_index warning[] );
foreach my $idx ( sort @indexes ) {
	delete($lynis_report_data{$idx});
}
#print Dumper(\%lynis_report_data);
