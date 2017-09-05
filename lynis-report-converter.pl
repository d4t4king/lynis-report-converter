#!/usr/bin/perl

use strict;
# turn off warnings so as not to confuse people
# unless debugging, etc.
#use warnings;
use feature qw( switch );
require 5.010;
no if $] ge '5.018', warnings => "experimental::smartmatch";
use Term::ANSIColor;
use Getopt::Long qw( :config no_ignore_case bundling );
use Data::Dumper;
use Module::Load::Conditional qw( can_load check_install requires );

my $VERSION = '0.3-beta';

my ($help,$input,$verbose,$excel,$output,$pdf,$debug,$json,$quiet,$xml,$showversion);
GetOptions(
	'h|help'		=>	\$help,
    'i|input=s'		=>	\$input,
	'v|verbose+'	=>	\$verbose,
	'E|excel'		=>	\$excel,
	'o|output=s'	=>	\$output,
	'p|pdf'			=>	\$pdf,
	'D|debug'		=>	\$debug,
	'j|json'		=>	\$json,
	'x|xml'			=>	\$xml,
	'q|quiet'		=>	\$quiet,
	'V|version'		=>	\$showversion,
);

&usage if ($help);
&usage if ((!$output) and (!$json) and (!$showversion));
 
#if ($verbose) { use warnings; }

my %to_bool = (	0 => 'false', 1 => 'true', "" => 'false' );
my %vm_mode = ( 0 => 'false', 1 => 'guest', 2 => 'host' );
my %to_long_severity = ( 'C' => 'Critical', 'S' => 'Severe', 'H' => 'High', 'M' => 'Medium', 'L' => 'Low', 'I' => 'Informational', '-' => 'NA', "" => 'NA' );
my %systemd_uf_status_color = (
	'enabled'	=>	'#00ff00',
	'disabled'	=>	'#ff0000',
	'static'	=>	'inherit',
	'masked'	=>	'goldenrod'
);
my $lynis_report;

if ($json) { $quiet = 1; }

my ($basename, $path, $suffix, $htmldoc, $format);

if ($excel) {
	$output = 'report.xlsx' unless ((defined($output)) and ($output ne ""));
	$format = 'excel';
} elsif ($pdf) {
	$output = 'report.pdf' unless ((defined($output)) and ($output ne ''));
	$htmldoc = "$$.html";
	$format = 'pdf';
} elsif ($json) {
	$output = undef unless ((defined($output)) and ($output ne ''));
	$format = 'json';
} elsif ($xml) {
	$output = 'report.xml' unless ((defined($output)) and ($output ne ''));
	$format = 'xml';
} else {
	$output = "report.html" unless ((defined($output)) and ($output ne ""));
	$htmldoc = $output;
	$format = 'html';
}

if (defined($input)) {
    $lynis_report = $input;
} else {
    $lynis_report = '/var/log/lynis-report.dat';
}

my $lynis_log = '/var/log/lynis.log';
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
	print colored("Looks like the audit has been run.", "green") unless ($quiet);
	print "\n" unless ($quiet);
} else {
	warn colored("Couldn't find one or more of the lynis output files.  Try running the audit again. \n", "bold red");
}

unless ($quiet) {
	print colored("Outputting report to $output, in ", "green");
	if ($excel) { print colored("Excel ", "green"); }
	elsif ($pdf) { print colored("PDF ", "green"); }
	elsif ($xml) { print colored("XML ", "green"); }
	elsif ($json) { print colored("JSON ", "green"); }
	else { print colored("HTML ", "green"); }
	print colored("format.", "green");
	print "\n";
}

# Handle inconsistent keys
&pop_inconsistent_keys($format, \%lynis_report_data);

# the report is easy to process, and actually doesn't contain the "audit findings"....just the data.
# but it is not our job to draw conclusions here, just present the findings of the tool.
open RPT, "<$lynis_report" or die colored("There was a problem opening the lynis report: $! ", "bold red");
while (my $line = <RPT>) {
	next if ($line =~ /^#/);								# skip commented lines
	#next if ($line =~ /Result.*allow\_url\_fopen.*/);		# This looks like a bug in the report output.  Skip it.
	#next if ($line =~ /Result.*expose\_php.*/);			# This looks like a bug in the report output.  Skip it.
	chomp($line);
	#if ($line =~ /swap_partition/) { print colored("$line\n", "bold magenta"); }
	my ($k,$v);
	if (scalar(split(/=/, $line)) > 2) {					# We got more than 2 elements after the split, 
															# so there is likely a equals in either the key 
															# or the value
		if ($line =~ /^(.+?)\=(.+)/) {
			$k = $1; $v = $2;
		} else {
			die colored("Unexpected match condition in splitting key/value pairs!", "bold red");
		}
	} else {
		($k, $v) = split(/=/, $line);
	}
	if ((!defined($k)) or ($k eq "")) { next; }				# something went wonky -- we didn't get a valid key. so skip
	if ((!defined($v)) or ($v eq "")) { 
		given($format) {
			when (/(excel|json)/) { $v = "NA"; }
			default { $v = "&nbsp;"; }	# fill with a blank(ish) value if nothing
		}
	}
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
			if ($tmp_v =~ /(?:\&nbsp\;|NA)/) {
				push @{$lynis_report_data{$k}}, $v;
			} else {
				push @{$lynis_report_data{$k}}, $tmp_v, $v;
			}
		}
	} else {
		$lynis_report_data{$k} = $v;
	}
}
close RPT or die colored("There was a problem closing the lynis report: $! ", "bold red");

foreach my $k ( qw(container notebook apparmor_enabled apparmor_policy_loaded ) ) {
	if ($lynis_report_data{$k} != 1) { $lynis_report_data{$k} = 0; }
}

if (ref($lynis_report_data{'automation_tool_running[]'}) eq 'ARRAY') {
	@{$lynis_report_data{'automation_tool_running[]'}} = &dedup_array($lynis_report_data{'automation_tool_running[]'}) if (ref($lynis_report_data{'automation_tool_running[]'}) eq 'ARRAY');
}
if (ref($lynis_report_data{'boot_service[]'}) eq 'ARRAY') {
	@{$lynis_report_data{'boot_service[]'}} = &dedup_array($lynis_report_data{'boot_service[]'}) if (ref($lynis_report_data{'boot_service[]'}) eq "ARRAY");
}
if (ref($lynis_report_data{'cronjob[]'}) eq 'ARRAY') {
	@{$lynis_report_data{'cronjob[]'}} = &dedup_array($lynis_report_data{'cronjob[]'}) if (ref($lynis_report_data{'cronjob[]'}) eq 'ARRAY');
}
if (ref($lynis_report_data{'nginx_config[]'}) eq 'ARRAY') {
	@{$lynis_report_data{'nginx_config[]'}} = &dedup_array($lynis_report_data{'nginx_config[]'}) if (ref($lynis_report_data{'nginx_config[]'}) eq 'ARRAY');
}

if (exists($lynis_report_data{'pam_auth_brute_force_protection_module[]'})) {
	if (ref($lynis_report_data{'pam_auth_brute_force_protection_module[]'}) eq 'ARRAY') {
		@{$lynis_report_data{'pam_auth_brute_force_protection_module[]'}} = &dedup_array($lynis_report_data{'pam_auth_brute_force_protection_module[]'});
	}
}

foreach my $key ( qw( certificates domainname journal_disk_size pop3_daemon imap_daemon printing_daemon ntp_daemon ntp_version apache_version systemd_version systemd_status systemd_builtin_components journal_coredumps_lastday running_service_tool service_manager localhost-mapped-to ) ) {
	# if element is not an array we don't need to flatten it
	if (ref($lynis_report_data{$key}) ne 'ARRAY') {
		warn colored("Skipped flatten $key since it's not an array.", "yellow") if ($verbose);
		next;
	}
	$lynis_report_data{$key} = &flatten(@{$lynis_report_data{$key}});
}

my $pass_score = &calc_password_complexity_score;

my (%warnings, %suggestions);

# process "string array" values delimited by a pipe (|)
foreach my $key ( sort keys %lynis_report_data ) {
	print "$key, ".ref($lynis_report_data{$key})." \n" if (($verbose) and ($verbose > 1));
	if (((ref($lynis_report_data{$key}) ne 'ARRAY') and
		(ref($lynis_report_data{$key}) ne 'HASH')) and
		($lynis_report_data{$key} =~ /\|/)) {
		print colored($key."\n", "green") if (($verbose) and ($verbose > 1));
		my @fs = split(/\|/, $lynis_report_data{$key});
		undef($lynis_report_data{$key});
		push @{$lynis_report_data{$key}}, @fs;
	}
}

my (@tests_skipped, @tests_executed);
my ($lynis_version);

if (exists($lynis_report_data{'tests_skipped'})) {
	@tests_skipped = @{$lynis_report_data{'tests_skipped'}};
	delete($lynis_report_data{'tests_skipped'});
}
if (exists($lynis_report_data{'tests_executed'})) {
	@tests_executed = @{$lynis_report_data{'tests_executed'}};
	delete($lynis_report_data{'tests_executed'});
}

if ($showversion) {
	&show_version;
}

if ($debug) {
	print colored("In debug mode.  Dumping data hash.\n", "yellow");
	print color('yellow');
	print Dumper(\%lynis_report_data);
	print color('reset');
	exit 1;
}

if ($json) {
	require JSON;
	# tidy up some of the "object" variables
	my @sduf;
	if (ref($lynis_report_data{'systemd_unit_file[]'}) eq 'ARRAY') {
		@sduf = @{$lynis_report_data{'systemd_unit_file[]'}};
		my @sduf_new;
		foreach my $uf ( @sduf ) {
			my ($name,$status) = split(/\|/, $uf);
			push @sduf_new, { 'name' => $name, 'state' => $status };
		}
		$lynis_report_data{'systemd_unit_file[]'} = \@sduf_new;
	}
	my @ipa;
       	if (ref($lynis_report_data{'installed_packages_array'}) eq 'ARRAY') {
		@ipa = @{$lynis_report_data{'installed_packages_array'}};
		my @ipa_new;
		foreach my $pkg ( @ipa ) {
			my ($name,$vers) = split(/\,/, $pkg);
			push @ipa_new, { 'name' => $name, 'version' => $vers };
		}
		$lynis_report_data{'installed_packages_array'} = \@ipa_new;
	}
	my @nlp;
	if (ref($lynis_report_data{'network_listen_port[]'}) eq 'ARRAY') {
		@nlp = @{$lynis_report_data{'network_listen_port[]'}};
		my @nlp_new;
		foreach my $pt (@nlp) {
			my ($port,$proto,$proc) = split(/\|/, $pt);
			push @nlp_new, { 'port' => $port, 'protocol' => $proto, 'owner_process' => $proc };
		}
		$lynis_report_data{'network_listen_port[]'} = \@nlp_new;
	}
	my @details;
       	if (ref($lynis_report_data{'details[]'}) eq 'ARRAY') {
		@details = @{$lynis_report_data{'details[]'}};
		my @det_new;
		foreach my $d ( @details ) {
			my ($id,$svc,$desc,$nmn) = split(/\|/, $d);
			my %descr;
			my @p = split(/\;/, $desc);
			foreach my $p ( @p ) { 
				my ($k, $v) = split(/\s*\:\s*/, $p);
				$descr{$k} = $v;
			}
			push @det_new, { 'id' => $id, 'service' => $svc, 'description' => \%descr };
		}
		$lynis_report_data{'details[]'} = \@det_new;
	}
	my @plugs;
       	if (ref($lynis_report_data{'plugin_enabled_phase1[]'}) eq 'ARRAY') {
		@plugs = @{$lynis_report_data{'plugin_enabled_phase1[]'}} unless (!exists($lynis_report_data{'plugin_enabled_phase1[]'}));
		my @plugs_new;
		foreach my $p ( @plugs ) {
			my ($name,$vers) = split(/\|/, $p);
			push @plugs_new, { 'name' => $name, 'version' => $vers };
		}
		$lynis_report_data{'plugin_enabled_phase1[]'} = \@plugs_new;
	}
	my @suggs;
       	if (ref($lynis_report_data{'suggestion[]'}) eq 'ARRAY') {
		@suggs = @{$lynis_report_data{'suggestion[]'}} unless (!exists($lynis_report_data{'suggestion[]'}));
		my @suggs_new;
		foreach my $s ( @suggs ) {
			my ($id,$desc,$sev,$f4) = split(/\|/, $s);
			push @suggs_new, { 'id' => $id, 'description' => $desc, 'severity' => $to_long_severity{$sev} }
		}
		$lynis_report_data{'suggestion[]'} = \@suggs_new;
	}
	my $json_obj = JSON->new->allow_nonref;
	my $json_text = $json_obj->encode( \%lynis_report_data );
	if ($output) {
		# open the file and write to it
		open OUT, ">$output" or die colored("There was a problem with the output file: $!", "bold red");
		print OUT $json_text."\n";
		close OUT
	} else {
		# it's more likely JSON consumers would want to pipe the output to another process
		# so print to STDOUT
		print $json_text;
	}

	# JSON is parsed directly from the report data array, using the JSON module.  So there should be no unhandled key-value pairs.
	# So just undef the hash.
	undef(%lynis_report_data);
} elsif ($xml) {
	require XML::Writer;
	my ($xmlout,$writer);
	if (($xml) and ($output)) {
		require IO::File;
		$xmlout = IO::File->new(">$output");
		$writer = XML::Writer->new('CONTENT'=>'self','DATA_MODE'=>1,'DATA_INDENT'=>2,'OUTPUT'=>$xmlout);
	} else {
		$writer = XML::Writer->new('CONTENT'=>'self','DATA_MODE'=>1,'DATA_INDENT'=>2,);
	}
	$writer->xmlDecl('UTF-8');
	$writer->startTag('lynisReportData');
	foreach my $key ( sort keys %lynis_report_data ) {
		if (ref($lynis_report_data{$key}) eq 'ARRAY') {
			my $tmpkey = $key;
			$tmpkey =~ s/\[\]//g;
			given ($key) {
				when (/home_directory\[\]/) {
					$writer->startTag("home_directories");
					foreach my $ele ( sort @{$lynis_report_data{$key}} ) {
						$writer->dataElement($tmpkey, $ele);
					}
					$writer->endTag();
				}
				when (/network_listen_port\[\]/) {
					$writer->startTag($tmpkey);
					foreach my $ele ( sort @{$lynis_report_data{$key}} ) {
						my ($port,$proto,$proc) = split(/\|/, $ele);
						$writer->startTag('network_listen_port', 'protocol' => $proto, 'owner_process' => $proc);
						$writer->characters($port);
						$writer->endTag();
					}
					$writer->endTag();
				}
				when (/installed_packages_array/) {
					$writer->startTag('installed_packages');
					foreach my $ele ( sort @{$lynis_report_data{$key}} ) {
						my ($name,$version) = split(/\,/, $ele);
						$writer->emptyTag('installed_package', 'name' => $name, 'version' => $version);
					}
					$writer->endTag();
				}
				when (/details\[\]/) {
					$writer->startTag('details');
					foreach my $ele ( sort @{$lynis_report_data{$key}} ) {
						my @parts = split(/\|/, $ele);
						$writer->emptyTag('detail', 'id' => $parts[0], 'service' => $parts[1], 'description' => $parts[2]);
					}
					$writer->endTag();
				}
				when (/warning\[\]/) {
					$writer->startTag('warnings');
					foreach my $ele ( sort @{$lynis_report_data{$key}} ) {
						my @parts = split(/\|/, $ele);
						$writer->emptyTag('warning', 'id' => $parts[0], 'description' => $parts[1], 'severity' => $parts[2], 'f4' => $parts[3]);
					}
					$writer->endTag();
				}
				when (/suggestion\[\]/) {
					$writer->startTag('suggestions');
					foreach my $ele ( sort @{$lynis_report_data{$key}} ) {
						my @parts = split(/\|/, $ele);
						$writer->emptyTag('suggestion', 'id' => $parts[0], 'description' => $parts[1], 'severity' => $parts[2], 'f4' => $parts[3]);
					}
					$writer->endTag();
				}
				when (/real_user\[\]/) {
					$writer->startTag('real_users');
					foreach my $ele ( sort @{$lynis_report_data{$key}} ) {
						my ($name,$uid) = split(/\,/, $ele);
						$writer->startTag('real_user', 'uid' => $uid);
						$writer->characters($name);
						$writer->endTag();
					}
					$writer->endTag();
				}
				default {
					$writer->startTag("${tmpkey}s");
					foreach my $ele ( sort @{$lynis_report_data{$key}} ) {
						$writer->dataElement($tmpkey, $ele);
					}
					$writer->endTag();
				}
			}
		} else {	
			if ($key =~ /.*\[\]$/) {
				$key =~ s/\[\]//g;
			}
			$writer->dataElement($key, $lynis_report_data{$key});
		}
	}
	$writer->endTag('lynisReportData');
	my $xml = $writer->end();
	if ($output) {
		$xmlout->close();
	} else {
		print $xml;
	}
	
	# XML is parsed directly from the report data array, using the XML::Writer module.  So there should be no unhandled key-value pairs.
	# So just undef the hash.
	undef(%lynis_report_data);
} elsif ($excel) {
	require Excel::Writer::XLSX;
	my $i = 0;
	# do the Excel thing....
	my $wb = Excel::Writer::XLSX->new($output);
	my $title_format = $wb->add_format( 'valign'=>'top', 'align'=>'left');
	$title_format->set_size('32');

	my $subtitle_format = $wb->add_format();
	$subtitle_format->set_size('24');

	my $subsub_format = $wb->add_format();
	$subsub_format->set_size('16');

	my $label_format = $wb->add_format('valign'=>'top','align'=>'left');
	$label_format->set_bold();

	my $version_format = $wb->add_format();
	$version_format->set_num_format( '0.00' );

	my $list_format = $wb->add_format('valign'=>'top', 'align'=>'left');
	$list_format->set_text_wrap();

	my $merge_format = $wb->add_format('valign'=>'top', 'align'=>'left');

	my $spanhead_format = $wb->add_format('valign'=>'top','align'=>'center');
	$spanhead_format->set_bold();
	$spanhead_format->set_size('16');

	### Summary Sheet Data
	my $summary_ws = $wb->add_worksheet('Summary');
	$summary_ws->merge_range('A1:C1', "lynis Asset Report", $title_format);
	$summary_ws->write('A2', "created by "); 
	$summary_ws->write_url('B2', "http://github.com/d4t4king/lynis_report.git", '', 'lynis_report');
	$summary_ws->write('A4', "Host Findings:", $subtitle_format);
	$summary_ws->write('A5', "hardening index:", $label_format);
	$summary_ws->write('B5', $lynis_report_data{'hardening_index'});
	$summary_ws->write('C5', 'auditor:', $label_format);
	$summary_ws->write('D5', $lynis_report_data{'auditor'});
	my %params; my $last_row_number = 1; my @table_data;
	if ((exists($lynis_report_data{'warning[]'})) and (ref($lynis_report_data{'warning[]'}) eq 'ARRAY')) {
		$summary_ws->write('A7', "warnings \(".scalar(@{$lynis_report_data{'warning[]'}})."\):", $subsub_format);
		#@header_row = [ 'Warning ID', 'Description', 'Severity', 'F4' ];
		if ($lynis_report_data{'warning[]'}[0] =~ /\|/) {
			foreach my $warn ( sort @{$lynis_report_data{'warning[]'}} ) {
				my ($warn_id,$warn_desc,$warn_sev,$warn_f4) = split(/\|/, $warn);
				push @table_data, [$warn_id,$warn_desc,$warn_sev,$warn_f4];
			}
		}
		#print STDERR Dumper(\@table_data);
		%params = (
			'data'				=>	\@table_data,
			'header_row'		=>	1,
			'autofilter'		=>	0,
			'banded_columns'	=>	0,
			'banded_rows'		=>	1,
			'columns'			=>	[
				{ 'header'		=>	'Warning ID' },
				{ 'header'		=>	'Description' },
				{ 'header'		=>	'Severity' },
				{ 'header'		=>	'F4' },
			]	
		);
		#print STDERR Dumper(\%params);
		$last_row_number = 8 + scalar(@table_data);
		$summary_ws->add_table("A8:D$last_row_number", \%params);
	} else { 
		$summary_ws->write('A7', "warnings (0):", $subsub_format);
	}
	@table_data = undef; my $next_row = 0;
	if ((exists($lynis_report_data{'suggestion[]'})) and (ref($lynis_report_data{'suggestion[]'}) eq 'ARRAY')) {
		$last_row_number++;
		$next_row = $last_row_number;
		$summary_ws->write("A${next_row}", "suggestions \(".scalar(@{$lynis_report_data{'suggestion[]'}})."\):", $subsub_format);
		$next_row++;
		#@header_row = [ 'Suggestion ID', 'Description', 'Severity', 'F4' ];
		if ($lynis_report_data{'suggestion[]'}[0] =~ /\|/) {
			foreach my $sugg (sort @{$lynis_report_data{'suggestion[]'}}) {
				my ($sugg_id,$sugg_desc,$sugg_sev,$sugg_f4) = split(/\|/, $sugg);
				push @table_data, [$sugg_id,$sugg_desc,$sugg_sev,$sugg_f4];
			}
		}
		%params = (
			'data'				=>	\@table_data,
			'header_row'		=>	1,
			'autofilter'		=>	0,
			'banded_columns'	=>	0,
			'banded_rows'		=>	1,
			'columns'			=>	[
				{ 'header'		=>	'Suggestion ID' },
				{ 'header'		=>	'Description' },
				{ 'header'		=>	'Severity' },
				{ 'header'		=>	'F4' },
			]
		);
		$last_row_number = $next_row + scalar(@table_data);
		$summary_ws->add_table("A${next_row}:D${last_row_number}", \%params);
	} else {
		$summary_ws->write("A$next_row", "suggestions (0):", $subsub_format);
	}
	@table_data = undef; 
	$next_row = $last_row_number;
	$next_row += 2;
	
	if ((exists($lynis_report_data{'manual[]'})) and (ref($lynis_report_data{'manual[]'}) eq 'ARRAY')) {
		$summary_ws->write("A${next_row}", "manual checks:", $subsub_format); $next_row++;
		foreach my $mc ( sort @{$lynis_report_data{'manual[]'}} ) {
			$summary_ws->write("A${next_row}", $mc, $merge_format);
			$next_row++;
		}
	} else {
		$summary_ws->write("A${next_row}", "manual checks (0):", $subsub_format); $next_row++;
	}
	$next_row += 2;
	if (exists($lynis_report_data{'vulnerable_package[]'})) {
		$summary_ws->write("A${next_row}", "vulnerable packages:", $subsub_format); $next_row++;
		if (ref($lynis_report_data{'vulnerable_package[]'}) eq 'ARRAY') {
			foreach my $vp ( sort @{$lynis_report_data{'vulnerable_package[]'}} ) {
				$summary_ws->write("A${next_row}", $vp); $next_row++;
			}
		} else {
			$summary_ws->write("A${next_row}", $lynis_report_data{'vulnerable_package[]'});
		}
	}

	### lynis report data
	my $lynis_ws = $wb->add_worksheet('lynis info');
	$lynis_ws->merge_range('A1:D1', 'lynis info:', $title_format);
	$lynis_ws->write('A2', 'lynis version:', $label_format); $lynis_ws->write('B2', $lynis_report_data{'lynis_version'}); $lynis_ws->write('C2', 'lynis tests done:', $label_format);	$lynis_ws->write('D2', $lynis_report_data{'lynis_tests_done'});
	$lynis_report_data{'lynis_update_available'} = 0 if ((defined($lynis_report_data{'lynis_update_available'})) and ($lynis_report_data{'lynis_update_available'} eq ""));
	$lynis_ws->write('A3', 'lynis update available:', $label_format); $lynis_ws->write('B3', uc($to_bool{$lynis_report_data{'lynis_update_available'}})); $lynis_ws->write('C3', 'license key:', $label_format); $lynis_ws->write('D3', $lynis_report_data{'license_key'});
	$lynis_ws->write('A4', 'report version:', $label_format); $lynis_ws->merge_range('B4:C4', "$lynis_report_data{'report_version_major'}\.$lynis_report_data{'report_version_minor'}", $version_format);
	$lynis_ws->write('A5', "test category:", $label_format); $lynis_ws->write('B5', $lynis_report_data{'test_category'}); $lynis_ws->write('C5', 'test group:', $label_format); $lynis_ws->write('D5', $lynis_report_data{'test_group'});
	$lynis_ws->write('A6', 'plugins enabled:', $label_format); $lynis_ws->write('B6', $lynis_report_data{'plugin_enabled[]'}); $lynis_ws->write('C6', 'plugin directory:', $label_format); $lynis_ws->write('D6', $lynis_report_data{'plugin_directory'});

	$lynis_ws->write('A8', 'report start time:', $label_format); $lynis_ws->write('B8', $lynis_report_data{'report_datetime_start'}); $lynis_ws->write('C8', 'report end time:', $label_format); $lynis_ws->write('D8', $lynis_report_data{'report_datetime_end'});
	$lynis_ws->write('A9', 'hostid1:', $label_format); $lynis_ws->merge_range('B9:D9', $lynis_report_data{'hostid'}, $merge_format);
	$lynis_ws->write('A10', 'hostid2:', $label_format); $lynis_ws->merge_range('B10:D10', $lynis_report_data{'hostid2'}, $merge_format);
	$lynis_ws->merge_range('A12:D12', 'plugin data:', $subtitle_format); 
	$i = 13;
	if (exists($lynis_report_data{'plugin_enabled_phase1[]'})) {
		$lynis_ws->write("A$i", "plugins enabled:", $subsub_format); $i++;
		$lynis_ws->write("A$i", "name", $label_format); $lynis_ws->write("B$i", "version", $label_format); $i++;
		if (ref($lynis_report_data{'plugin_enabled_phase1[]'}) eq 'ARRAY') {
			foreach my $plug ( sort @{$lynis_report_data{'plugin_enabled_phase1[]'}} ) {
				if ($plug =~ /\|/) {
					my ($n, $v, $j) = split(/\|/, $plug);
					$lynis_ws->write("A$i", $n); $lynis_ws->write("B$i", $v); $i++;
				} else {
					$lynis_ws->write("A$i", $plug); $i++;
				}
			}
		}
	}
	$i++;		
	$lynis_ws->write("A$i", "plugin -> firewall:", $subsub_format); $i++;
	$lynis_ws->write("A$i", 'iptables list:', $label_format); $i++;
	if (exists($lynis_report_data{'plugin_firewall_iptables_list'})) {
		if (ref($lynis_report_data{'plugin_firewall_iptables_list'}) eq 'ARRAY') {
			foreach my $ipt ( sort @{$lynis_report_data{'plugin_firewall_iptables_list'}} ) {
				$lynis_ws->write("A$i", $ipt); $i++;
			}
		} else {
			$lynis_ws->write("A$i", $lynis_report_data{'plugin_firewall_iptables_list'}); $i++;
		}
	} else {
		$lynis_ws->write("A$i", "N/A");
	}
	$i++;
	$lynis_ws->merge_range("A$i:D$i", 'plugin -> processes:', $subsub_format); $i++;
	$lynis_ws->merge_range("A$i:D$i", "all processes", $label_format); $i++;
	if (exists($lynis_report_data{'plugin_processes_allprocesses'})) {
		if (ref($lynis_report_data{'plugin_processes_allprocesses'}) eq 'ARRAY') {
			foreach my $proc ( sort @{$lynis_report_data{'plugin_processes_allprocesses'}} ) {
				$lynis_ws->merge_range("A$i:D$i", $proc, $merge_format); $i++;
			}
		} else {
			$lynis_ws->merge_range("A$i:D$i", $lynis_report_data{'plugin_processes_allprocesses'}, $merge_format); $i++;
		}
	} else {
		$lynis_ws->write("A$i", "N/A");
	}
	$i++;

	### host infor
	my $host_ws = $wb->add_worksheet('host info');
	$host_ws->write('A1', "host info:", $title_format);
	$host_ws->write('A2', 'hostname:', $label_format); $host_ws->write('B2', $lynis_report_data{'hostname'}); 
	$host_ws->write('C2', 'domainname:', $label_format); $host_ws->write('D2', $lynis_report_data{'domainname'}); 
	$host_ws->write('E2', 'resolv.conf domain:', $label_format); $host_ws->write('F2', $lynis_report_data{'resolv_conf_domain'});
	$host_ws->write('A3', 'os:', $label_format); $host_ws->write('B3', $lynis_report_data{'os'}); 
	$host_ws->write('C3', 'os fullname:', $label_format); $host_ws->write('D3', $lynis_report_data{'os_fullname'}); 
	$host_ws->write('E3', 'os version:', $label_format); $host_ws->write('F3', $lynis_report_data{'os_version'});
	$host_ws->write('A4', 'GRsecurity:', $label_format); $host_ws->write('B4', uc($to_bool{$lynis_report_data{'framework_grsecurity'}})); 
	$host_ws->write('C4', 'SELinux:', $label_format); $host_ws->write('D4', uc($to_bool{$lynis_report_data{'framework_selinux'}})); 
	$host_ws->write('E4', 'memory:', $label_format); $host_ws->write('F4', "$lynis_report_data{'memory_size'} $lynis_report_data{'memory_units'}");
	$host_ws->write('A5', 'linux version:', $label_format); $host_ws->write('B5', $lynis_report_data{'linux_version'}); 
	$host_ws->write('C5', 'PAE enabled:', $label_format); $host_ws->write('D5', uc($to_bool{$lynis_report_data{'cpu_pae'}})); 
	$host_ws->write('E5', 'NX enabled:', $label_format); $host_ws->write('F5', uc($to_bool{$lynis_report_data{'cpu_nx'}}));
	$host_ws->write('A6', 'available shells:', $label_format); $host_ws->write('B6', join("\n", @{$lynis_report_data{'available_shell[]'}}), $list_format); 
	$host_ws->write('C6', 'locatedb:', $label_format); $host_ws->write('D6', $lynis_report_data{'locate_db'}, $merge_format); $host_ws->write('E6', 'uptime (days):', $label_format); $host_ws->write('F6', $lynis_report_data{'uptime_in_days'}, $merge_format);
	$host_ws->write('A7', 'vm:', $label_format); $host_ws->write('B7', $vm_mode{$lynis_report_data{'vm'}}); 
	$host_ws->write('C7', 'vm_type:', $label_format); $host_ws->write('D7', $lynis_report_data{'vmtype'}); 
	$host_ws->write('E7', 'uptime(secs):', $label_format); $host_ws->write('F7', $lynis_report_data{'uptime_in_seconds'});
	$lynis_report_data{'notebook'} = 0 if ((!exists($lynis_report_data{'notbook'})) or ($lynis_report_data{'notebook'} eq ''));
	$host_ws->write('A8', 'is notebook/laptop:', $label_format); $host_ws->write('B8', uc($to_bool{$lynis_report_data{'notebook'}}));
	$host_ws->write('C8', 'is container:', $label_format); $host_ws->write('D8', uc($to_bool{$lynis_report_data{'container'}}));
	$host_ws->write('A9', 'binary paths:', $label_format); $host_ws->write('B9', $lynis_report_data{'binary_paths'});
	$host_ws->write('C9', 'certificate count:', $label_format); $host_ws->write('D9', $lynis_report_data{'certificates'});
	$host_ws->write('A10', 'authorized default USB devices:', $label_format); $host_ws->write('B10', join("\n", @{$lynis_report_data{'usb_authorized_default_device[]'}}), $list_format); 
	$host_ws->write('C10', 'certificates:', $label_format); 
	if (ref($lynis_report_data{'certificate[]'}) eq 'ARRAY') {
		$host_ws->write('D10', join("\n", @{$lynis_report_data{'certificate[]'}}));
	} else {
		$host_ws->write('D10', $lynis_report_data{'certificate[]'});
	}
	$host_ws->write('C11', 'valid certificates:', $label_format); 
	if (ref($lynis_report_data{'valid_certificate[]'}) eq 'ARRAY') {
		$host_ws->write('D11', join("\n", @{$lynis_report_data{'valid_certificate[]'}}));
	} else {
		$host_ws->write('D11', $lynis_report_data{'valid_certificate[]'});
	}
	$host_ws->write('C12', 'expired certificates:', $label_format); 
	if (ref($lynis_report_data{'expired_certificate[]'}) eq 'ARRAY') {
		$host_ws->write('D12', join("\n", @{$lynis_report_data{'expired_certificate[]'}}));
	} else {
		$host_ws->write('D12', $lynis_report_data{'expired_certificate[]'});
	}

	$host_ws->write('A13', 'cron jobs:', $label_format); 
	$i = 14;
	if ((exists($lynis_report_data{'cronjob[]'})) and (ref($lynis_report_data{'cronjob[]'}) eq 'ARRAY')) {
		foreach my $job ( sort @{$lynis_report_data{'cronjob[]'}} ) {
			$job =~ s/\,/ /g;
			#$host_ws->write("A$i", $job);
			$host_ws->merge_range("A$i:B$i", $job, $merge_format);
			$i++;
		}
	} else {
		$host_ws->write("A$i", $lynis_report_data{'cronjob[]'});
	}
	$i++;
	$host_ws->write("A$i", "logging info:", $subsub_format); $i++;
	$host_ws->write("A$i", "log rotation tool:", $label_format); $host_ws->write("B$i", $lynis_report_data{'log_rotation_tool'}); $host_ws->write("C$i", "log rotation config found:", $label_format); $host_ws->write("D$i", uc($to_bool{$lynis_report_data{'log_rotation_config_found'}}));
	$i += 2; $host_ws->write("A$i", "log directories:", $subsub_format); $i++;
	if ((exists($lynis_report_data{'log_directory[]'})) and (ref($lynis_report_data{'log_directory[]'}) eq 'ARRAY')) {
		foreach my $dir ( sort @{$lynis_report_data{'log_directory[]'}} ) {
			$host_ws->merge_range("A$i:C$i", $dir, $merge_format); $i++;
		}
	} else {
		$host_ws->merge_range("A$i:C$i", $lynis_report_data{'log_directory[]'}, $merge_format);
	}
	$i++; $host_ws->write("A$i", "open log files:", $subsub_format); $i++;
	if ((exists($lynis_report_data{'open_logfile[]'})) and (ref($lynis_report_data{'open_logfile[]'}) eq 'ARRAY')) {
		foreach my $f ( sort @{$lynis_report_data{'open_logfile[]'}} ) {
			$host_ws->merge_range("A$i:C$i", $f, $merge_format); $i++;
		}
	} else {
		$host_ws->merge_range("A$i:C$i", $lynis_report_data{'open_logfile[]'}, $merge_format);
	}
	$i++; $host_ws->write("A$i", "open empty log files:", $subsub_format); $i++;
	if ((exists($lynis_report_data{'open_empty_log_file[]'})) and (ref($lynis_report_data{'open_empty_log_file[]'}) eq 'ARRAY')) {
		foreach my $f ( sort @{$lynis_report_data{'open_empty_log_file[]'}} ) {
			$host_ws->merge_range("A$i:C$i", $f, $merge_format); $i++;
		}
	} else {
		$host_ws->merge_range("A$i:C$i", $lynis_report_data{'open_empty_log_file[]'}, $merge_format);
	}

	### network infdo
	my $net_ws = $wb->add_worksheet('network info');
	$net_ws->write('A1', "network info:", $title_format);
	$net_ws->write('A2', 'ipv6 mode:', $label_format); $net_ws->write('B2', $lynis_report_data{'ipv6_mode'}); 
	$net_ws->write('C2', "ipv6 only:", $label_format); $net_ws->write('D2', uc($to_bool{$lynis_report_data{'ipv6_only'}}));
	$net_ws->write('A3', 'network interfaces:', $label_format); $net_ws->write('B3', join("\r\n", @{$lynis_report_data{'network_interface[]'}}));
	if (ref($lynis_report_data{'localhost-mapped-to'}) eq 'ARRAY') {
		$net_ws->write('C3', 'localhost mapped to:', $label_format); $net_ws->write('D3', join("\r\n", @{$lynis_report_data{'localhost-mapped-to'}}));
	} else {
		$net_ws->write('C3', 'localhost mapped to:', $label_format); $net_ws->write('D3', $lynis_report_data{'localhost-mapped-to'});
	}
	$net_ws->write('A4', 'ipv4 addresses', $label_format); $net_ws->write('B4', join("\r\n", @{$lynis_report_data{"network_ipv4_address[]"}}));
	$net_ws->write('A5', 'ipv6 addresses', $label_format); $net_ws->write('B5', join("\r\n", @{$lynis_report_data{"network_ipv6_address[]"}}));
	$net_ws->write('A6', 'default gateway', $label_format); $net_ws->write('B6', $lynis_report_data{'default_gateway[]'});
	$net_ws->write('A7', 'mac addresses', $label_format); 
	if (exists($lynis_report_data{'network_mac_address[]'})) {
		if (ref($lynis_report_data{'network_mac_address[]'}) eq 'ARRAY') {
			$net_ws->write('B7', join("\n", @{$lynis_report_data{'network_mac_address[]'}}));
		} else {
			$net_ws->write('B7', $lynis_report_data{'network_mac_address[]'});
		}
	} else {
		$net_ws->write('B7', "N/A");
	}
	$net_ws->write('C7', 'name cache used:', $label_format); $net_ws->write('D7', uc($to_bool{$lynis_report_data{'name_cache_used'}}), $merge_format);
	$net_ws->write('A8', 'name servers:', $label_format); 
	if (exists($lynis_report_data{'nameserver[]'})) {
		if (ref($lynis_report_data{'name_server[]'}) eq 'ARRAY') {
			$net_ws->write('B8', join("\n", @{$lynis_report_data{'nameserver[]'}}), $merge_format);
		} else {
			$net_ws->write('B8', $lynis_report_data{'nameserver[]'}, $merge_format);
		}
	} else {
		$net_ws->write('B8', "N/A");
	}
	$net_ws->write('A9', 'resolv.conf search domain', $label_format); $net_ws->write('B9', $lynis_report_data{'resolv_conf_search_domain[]'});
	$net_ws->write('A11', 'open ports:', $subsub_format); 
	if ((exists($lynis_report_data{'network_listen_port[]'})) and (ref($lynis_report_data{'network_listen_port[]'}) eq 'ARRAY')) {
		$net_ws->write('A12', "ip address", $label_format); $net_ws->write('B12', 'port', $label_format); $net_ws->write('C12', 'protocol', $label_format); $net_ws->write('D12', 'daemon/process', $label_format); $net_ws->write('E12', '???', $label_format);
		$i = 13;
		foreach my $rec ( sort @{$lynis_report_data{'network_listen_port[]'}} ) {
			#print STDERR colored("$rec \n", "bold magenta");
			my ($ipp,$pr,$d,$u) = split(/\|/, $rec);
			my ($ip, $port);
			if (grep(/\:/, split(//, $ipp)) > 1) {
				my @parts = split(/\:/, $ipp);
				$port = pop(@parts);					# gets the last element of the array.  like	$parts[-1];
				$ip = join(":", @parts);				# should only be the remaining parts, which should be the ipv6 addr
			} else {
				# must be IPv4
				($ip,$port) = split(/\:/, $ipp);
			}
			$net_ws->write("A$i", $ip); $net_ws->write("B$i", $port); $net_ws->write("C$i", $pr); $net_ws->write("D$i", $d); $net_ws->write("E$i", $u);
			$i++;
		}
	} else {
		warn colored("network_listen_port[] not an array!", "yellow");
	}

	### security info
	my $sec_ws = $wb->add_worksheet('security info');
	$sec_ws->write('A1', "security info:", $title_format);
	$sec_ws->write('A2', 'host firewall installed:', $label_format); $sec_ws->write('B2', uc($to_bool{$lynis_report_data{'firewall_installed'}}));
	$sec_ws->write('C2', 'firewall software:', $label_format); $sec_ws->write('D2', $lynis_report_data{'firewall_software[]'});
	$sec_ws->write('E2', 'firewall empty ruleset:', $label_format); $sec_ws->write('F2', uc($to_bool{$lynis_report_data{'firewall_empty_ruleset'}}));
	$sec_ws->write('G2', 'firewall active:', $label_format); $sec_ws->write('H2', uc($to_bool{$lynis_report_data{'firewall_active'}}));
	$sec_ws->write('A3', 'package audit tool found', $label_format); $sec_ws->write('B3', uc($to_bool{$lynis_report_data{'package_audit_tool_found'}}));
	$sec_ws->write('C3', 'package audit tool;', $label_format); $sec_ws->write('D3', $lynis_report_data{'package_audit_tool'});
	$sec_ws->write('E3', 'vulnerable packages found:', $label_format); $sec_ws->write('F3', uc($to_bool{$lynis_report_data{'vulnerable_packages_found'}}));
	$sec_ws->write('G3', 'package manager:', $label_format); $sec_ws->write('H3', $lynis_report_data{'package_manager[]'});
	$sec_ws->write('A4', 'two-factor authentication enabled:', $label_format); $sec_ws->write('B4', uc($to_bool{$lynis_report_data{'authentication_two_factor_enabled'}}));
	$sec_ws->write('C4', 'two-factor authentication required:', $label_format); $sec_ws->write('D4', uc($to_bool{$lynis_report_data{'authentication_two_factor_required'}}));
	$sec_ws->write('E4', 'LDAP PAM module enabled:', $label_format); $sec_ws->write('F4', uc($to_bool{$lynis_report_data{'ldap_pam_enabled'}}));
	$sec_ws->write('G4', 'LDAP authentication enabled:', $label_format); $sec_ws->write('H4', uc($to_bool{$lynis_report_data{'ldap_auth_enabled'}}));
	$sec_ws->write('A5', 'minimum password length:', $label_format); $sec_ws->write('B5', $lynis_report_data{'minimum_password_length'});
	$sec_ws->write('C5', 'maximum password days:', $label_format); $sec_ws->write('D5', $lynis_report_data{'password_max_days'});
	$sec_ws->write('E5', 'minimum password days:', $label_format); $sec_ws->write('F5', $lynis_report_data{'password_min_days'});
	$sec_ws->write('G5', 'maximum password retries:', $label_format); $sec_ws->write('H5', $lynis_report_data{'max_password_retry'});
	$sec_ws->write('A6', 'password complexity score:', $label_format); $sec_ws->write_formula('B6', "=DEC2BIN($pass_score)");
	$sec_ws->write('C6', 'PAM cracklib found:', $label_format); $sec_ws->write('D6', uc($to_bool{$lynis_report_data{'pam_cracklib'}}));
	$sec_ws->write('E6', 'password strength tested:', $label_format); $sec_ws->write('F6', uc($to_bool{$lynis_report_data{'password_strength_tested'}}));
	$sec_ws->write('G6', 'PAM password quality:', $label_format); $sec_ws->write('H6', $lynis_report_data{'pam_pwquality'});
	if (ref($lynis_report_data{'pam_auth_brute_force_protection_module'}) eq 'ARRAY') {
		$sec_ws->write('A7', 'PAM brute force protection module:', $label_format); $sec_ws->write('B7', join("\n", @{$lynis_report_data{'pam_auth_brute_force_protection_module[]'}}));
	} else {
		$sec_ws->write('A7', 'PAM brute force protection module:', $label_format); $sec_ws->write('B7', $lynis_report_data{'pam_auth_brute_force_protection_module[]'});
	}
	$sec_ws->write('C7', 'failed logins logged:', $label_format); $sec_ws->write('D7', uc($to_bool{$lynis_report_data{'auth_failed_logins_logged'}}));
	$sec_ws->write('E7', 'apparmor enabled:', $label_format); $sec_ws->write('F7', uc($to_bool{$lynis_report_data{'apparmor_enabled'}}));
	$sec_ws->write('G7', 'apparmor policy loaded:', $label_format); $sec_ws->write('H7', uc($to_bool{$lynis_report_data{'apparmor_policy_loaded'}}));
	$sec_ws->write('A8', 'authentication brute force protection:', $label_format); $sec_ws->write('B8', uc($to_bool{$lynis_report_data{'authentication_brute_force_protection'}}));
	$sec_ws->write('A8', 'file integrity tool installed:', $label_format); $sec_ws->write('B8', uc($to_bool{$lynis_report_data{'file_integrity_tool_installed'}}));
	$sec_ws->write('C8', 'file integreity tool(s):', $label_format); $sec_ws->write('D8', $lynis_report_data{'file_integrity_tool[]'});
	$sec_ws->write('E8', 'automation tool present:', $label_format); $sec_ws->write('F8', uc($to_bool{$lynis_report_data{'automation_tool_present'}}));
	$sec_ws->write('G8', 'automation tool(s):', $label_format); $sec_ws->write('H8', $lynis_report_data{'automation_tool_running[]'});
	$sec_ws->write('A9', 'malware scanner installed', $label_format); $sec_ws->write('B9', uc($to_bool{$lynis_report_data{'malware_scanner_installed'}}));
	$sec_ws->write('C9', 'malware scanner(s):', $label_format); $sec_ws->write('D9', $lynis_report_data{'malware_scanner[]'});
	$sec_ws->write('E9', 'compiler installed:', $label_format); $sec_ws->write('F9', uc($to_bool{$lynis_report_data{'compiler_installed'}}));
	$sec_ws->write('G9', 'compiler(s):', $label_format); $sec_ws->write('H9', $lynis_report_data{'compiler[]'});
	$sec_ws->write('A10', 'IDS/IPS tooling', $label_format); 
	if (exists($lynis_report_data{'ids_ips_tooling'})) {
		if (ref($lynis_report_data{'ids_ips_tooling'}) eq 'ARRAY') {
			$sec_ws->write('B10', join("\n", @{$lynis_report_data{'ids_ips_tooling'}}), $merge_format);
		} else {
			$sec_ws->write('B10', $lynis_report_data{'ids_ips_tooling'}, $merge_format);
		}
	} else {
		$sec_ws->write('B10', 'NA', $merge_format);
	}
	if (exists($lynis_report_data{'fail2ban_config'})) {
		$sec_ws->write('C10', 'fail2ban config file(s):', $label_format);
		$sec_ws->write('D10', $lynis_report_data{'fail2ban_config'}, $merge_format);
	} else {
		$sec_ws->write('D10', 'NA', $merge_format);
	}
	if (exists($lynis_report_data{'fail2ban_enabled_service[]'})) {
		$sec_ws->write('E10', 'fail2ban enabled service(s):', $label_format);
		if (ref($lynis_report_data{'fail2ban_enabled_service[]'}) eq 'ARRAY') {
			$sec_ws->write('F10', join("\n", @{$lynis_report_data{'fail2ban_enabled_service[]'}}), $merge_format);
		} else {
			$sec_ws->write('F10', $lynis_report_data{'fail2ban_enabled_service[]'}, $merge_format);
		}
	}
	$sec_ws->write("G10", "session timeout enabled:", $label_format);
	$sec_ws->write("H10", uc($to_bool{$lynis_report_data{'session_timeout_enabled'}}));
	$sec_ws->merge_range('A12:B12', 'real users:', $subsub_format); $sec_ws->merge_range('C12:D12', 'home directories:', $subsub_format);
	$sec_ws->write('A13', 'name', $label_format); $sec_ws->write('B13', 'uid', $label_format);
	$i = 14;
	if ((exists($lynis_report_data{'real_user[]'})) and (ref($lynis_report_data{'real_user[]'}) eq 'ARRAY')) {
		foreach my $usr ( sort @{$lynis_report_data{'real_user[]'}} ) {
			my ($n, $uid) = split(/\,/, $usr);
			$sec_ws->write("A$i", $n); $sec_ws->write("B$i", $uid); $i++; 
		}
	} else {
		warn colored("real_user[] not found or not an array!", "yellow");
		print STDERR color('yellow');
		print STDERR ref($lynis_report_data{'real_user[]'})."\n";
		print STDERR Dumper($lynis_report_data{'real_user[]'});
		print STDERR color('reset');
	}
	$i = 13;
	if ((exists($lynis_report_data{'home_directory[]'})) and (ref($lynis_report_data{'home_directory[]'}) eq 'ARRAY')) {
		foreach my $dir ( sort @{$lynis_report_data{'home_directory[]'}} ) {
			$sec_ws->write("C$i", $dir); $i++;
		}
	} else {
		warn colored("home_directory[] not found or not an array!", "yellow");
		print STDERR color("yellow");
		print STDERR ref($lynis_report_data{'home_directory[]'})."\n";
		print STDERR Dumper($lynis_report_data{'home_directory[]'});
		print STDERR color('reset');
	}
	$i++;
	$sec_ws->write("A$i", "PAM modules:", $subsub_format); $i++;
	if ((exists($lynis_report_data{'pam_module[]'})) and (ref($lynis_report_data{'pam_module[]'}) eq 'ARRAY')) {
		foreach my $mod ( sort @{$lynis_report_data{'pam_module[]'}} ) {
			$sec_ws->write("A$i", $mod); $i++;
		}
	} else {
		warn colored("pam_module[] not found or not an array!", "yellow");
		print STDERR color("yellow");
		print STDERR ref($lynis_report_data{'pam_module[]'})."\n";
		print STDERR Dumper($lynis_report_data{'pam_module[]'});
		print STDERR color('reset');
	}

	### boot info
	my $boot_ws = $wb->add_worksheet('boot info');
	$boot_ws->write('A1', "boot info:", $title_format);
	$boot_ws->write('A2', 'UEFI booted:', $label_format); $boot_ws->write('B2', uc($to_bool{$lynis_report_data{'boot_uefi_booted'}}));
	$boot_ws->write('C2', 'UEFI booted secure:', $label_format); $boot_ws->write('D2', uc($to_bool{$lynis_report_data{'boot_uefi_booted_secure'}}));
	$boot_ws->write('E2', 'boot loader:', $label_format); $boot_ws->write('F2', $lynis_report_data{'boot_loader'});
	$boot_ws->write('A3', 'default runlevel:', $label_format); $boot_ws->write('B3', $lynis_report_data{'linux_default_runlevel'});
	$boot_ws->write('C3', 'boot service tool:', $label_format); $boot_ws->write('D3', $lynis_report_data{'boot_service_tool'});
	$i = 5;
	if (exists($lynis_report_data{'boot_service[]'})) {
		$boot_ws->write("A$i", "services started at boot:", $subsub_format); $i++;
		if (ref($lynis_report_data{'boot_service[]'}) eq 'ARRAY') {
			foreach my $bs ( sort @{$lynis_report_data{'boot_service[]'}} ) {
				$boot_ws->write("A$i", $bs); $i++;
			}
		} else {
			$boot_ws->write("A$i", $lynis_report_data{'boot_service[]'});
		}
	}

	### kernel inso
	my $kernel_ws = $wb->add_worksheet('kernel info');
	$kernel_ws->write('A1', "kernel info:", $title_format);
	$kernel_ws->write('A2', "kernel version:", $label_format);
	$kernel_ws->write('B2', $lynis_report_data{'linux_kernel_version'});
	$kernel_ws->write('C2', 'full kernel version:', $label_format);
	$kernel_ws->write('D2', $lynis_report_data{'os_kernel_version_full'});
	$kernel_ws->write('A3', 'kernel release version:', $label_format);
	$kernel_ws->write('B3', $lynis_report_data{'linux_kernel_release'});
	$kernel_ws->write('C3', 'kernel IO scheduler:', $label_format);
	if (exists($lynis_report_data{'linux_kernel_io_scheduler[]'})) {
		if (ref($lynis_report_data{'linux_kernel_io_scheduler[]'}) eq 'ARRAY') {
			$kernel_ws->write('D3', join("\n", @{$lynis_report_data{'linux_kernel_io_scheduler[]'}}));
		} else {
			$kernel_ws->write('D3', $lynis_report_data{'linux_kernel_io_scheduler[]'});
		}
	} else {
		$kernel_ws->write('D3', 'N/A');
	}
	$kernel_ws->write('A4', 'linux kernel type:', $label_format);
	$kernel_ws->write('B4', $lynis_report_data{'linux_kernel_type'});
	$kernel_ws->write('C4', 'number of kernels available:', $label_format);
	$kernel_ws->write('D4', $lynis_report_data{'linux_amount_of_kernels'});
	$kernel_ws->write('A5', 'linux (kernel) config file:', $label_format);
	$kernel_ws->write('B5', $lynis_report_data{'linux_config_file'});
	$i = 7;
	if (exists($lynis_report_data{'loaded_kernel_module[]'})) {
		$kernel_ws->write("A$i", "loaded kernel modules:", $subsub_format);  $i++;
		if (ref($lynis_report_data{'loaded_kernel_module[]'}) eq 'ARRAY') {
			foreach my $mod ( sort @{$lynis_report_data{'loaded_kernel_module[]'}} ) {
				$kernel_ws->write("A$i", $mod);  $i++;
			}
		} else {
			$kernel_ws->write("A$i", $lynis_report_data{'loaded_kernel_module[]'});
		}
	}

	### filesystem/journalling info
	my $fs_ws = $wb->add_worksheet('filesystem info');
	$fs_ws->write('A1', "filesystem info:", $title_format);
	$fs_ws->write('A2', "journal disk size:", $label_format); $fs_ws->write('B2', $lynis_report_data{'journal_disk_size'});
	$fs_ws->write('A3', "most recent journal coredump:", $label_format); $fs_ws->write('B3', $lynis_report_data{'journal_coredump_lastday'});
	$fs_ws->write('A4', 'oldest boot date on journal:', $label_format); $fs_ws->write('B4', $lynis_report_data{'journal_oldest_bootdate'});
	$fs_ws->write('A5', 'journal contains errors:', $label_format); $fs_ws->write('B5', uc($to_bool{$lynis_report_data{'journal_contains_errors'}}));
	$fs_ws->write('A6', 'journal boot logging enabled:', $label_format); $fs_ws->write('B6', uc($to_bool{$lynis_report_data{'journal_bootlogs'}}));
	$fs_ws->write("C2", 'swap partitions:', $label_format);
	if (exists($lynis_report_data{'swap_partition[]'})) {
		if (ref($lynis_report_data{'swap_partition[]'}) eq 'ARRAY') {
			$fs_ws->write("D2", join("\n", $lynis_report_data{'swap_partition[]'}));
		} else {
			$lynis_report_data{'swap_partition[]'} =~ s/,/\n/g;
			$fs_ws->write("D2", $lynis_report_data{'swap_partition[]'});
		}
	} else {
		$fs_ws->write("D2", 'N/A');
	}
	$fs_ws->write('C3', "LVM volume group(s):", $label_format);
	if (exists($lynis_report_data{'lvm_volume_group[]'})) {
		if (ref($lynis_report_data{'lvm_volume_group[]'}) eq 'ARRAY') {
			$fs_ws->write("D3", join("\n", @{$lynis_report_data{'lvm_volume_group[]'}}));
		} else {
			$lynis_report_data{'lvm_volume_group[]'} =~ s/,/\n/g;
			$fs_ws->write("D3", $lynis_report_data{'lvm_volume_group[]'});
		}
	} else {
		$fs_ws->write('D3', 'N/A');
	}
	$fs_ws->write('C4', 'LVM volume(s):', $label_format);
	if (exists($lynis_report_data{'lvm_volume[]'})) {
		if (ref($lynis_report_data{'lvm_volume[]'}) eq 'ARRAY') {
			$fs_ws->write("D4", join("\n", @{$lynis_report_data{'lvm_volume[]'}}));
		} else {
			$lynis_report_data{'lvm_volume[]'} =~ s/,/\n/g;
			$fs_ws->write('D4', $lynis_report_data{'lvm_volume[]'});
		}
	} else {
		$fs_ws->write("D4", "N/A");
	}
	$fs_ws->write("C5", "ext filesystems:", $label_format);
	if (exists($lynis_report_data{'file_systems_ext[]'})) {
		if (ref($lynis_report_data{'file_systems_ext[]'}) eq 'ARRAY') {
			$fs_ws->write("D5", join("\n", @{$lynis_report_data{'file_systems_ext[]'}}));
		} else {
			$lynis_report_data{'file_systems_ext[]'} =~ s/,/\n/g;
			$fs_ws->write("D5", $lynis_report_data{'file_systems_ext[]'});
		}
	} else {
		$fs_ws->write("D5", "N/A");
	}
	$i = 8;
	if (exists($lynis_report_data{'journal_meta_data'})) {
		$fs_ws->merge_range("A$i:B$i", 'journal metadata:', $subsub_format); $i++;
		if (ref($lynis_report_data{'journal_meta_data'}) eq 'ARRAY') {
			foreach my $r ( @{$lynis_report_data{'journal_meta_data'}} ) {
				$fs_ws->merge_range("A$i:B$i", $r, $merge_format); $i++;
			}
		} else {
			$fs_ws->merge_range("A$i:B$i", $lynis_report_data{'journal_meta_data'}, $merge_format); $i++;
		}
	}
	if (exists($lynis_report_data{'deleted_file[]'})) {
		$fs_ws->write("A$i", 'deleted files still on the filesystem:', $subsub_format); $i++;
		if (ref($lynis_report_data{'deleted_file[]'}) eq 'ARRAY') {
			foreach my $df ( sort @{$lynis_report_data{'deleted_file[]'}} ) {
				$fs_ws->write("A$i", $df); $i++;
			}
		} else {
			$fs_ws->write("A$i", $lynis_report_data{'deleted_file[]'});
		}
	}

	### service info
	my $svc_ws = $wb->add_worksheet('service info');
	$svc_ws->write('A1', "service info:", $title_format);
	$i = 3;
	foreach my $prog ( sort qw( redis ntp_daemon mysql ssh_daemon dhcp_client arpwatch audit_daemon postgresql linux_auditd nginx ) ) {
		if ((!defined($lynis_report_data{"${prog}_running"})) or ($lynis_report_data{"${prog}_running"} eq "")) {
			$lynis_report_data{"${prog}_running"} = 0;
		}
		$svc_ws->write("A$i", "$prog running:", $label_format); $svc_ws->write("B$i", uc($to_bool{$lynis_report_data{"${prog}_running"}}));
		$i++;
	}
	my $i_hold = $i; # $i should be 13
	$i = 3;
	$svc_ws->write("C$i", "imap daemon:", $label_format); $svc_ws->write("D$i", $lynis_report_data{"imap_daemon"}); $i++;
	$svc_ws->write("C$i", "ntp daemon:", $label_format); $svc_ws->write("D$i", $lynis_report_data{"ntp_daemon"}); $i++;
	$svc_ws->write("C$i", "pop3 daemon:", $label_format); $svc_ws->write("D$i", $lynis_report_data{"pop3_daemon"}); $i++;
	$svc_ws->write("C$i", "printing daemon", $label_format); $svc_ws->write("D$i", $lynis_report_data{"printing_daemon"}); $i++;
	$svc_ws->write("C$i", "running service tool:", $label_format); $svc_ws->write("D$i", $lynis_report_data{"running_service_tool"}); $i++;
	if ((exists($lynis_report_data{'scheduler[]'})) and (ref($lynis_report_data{'scheduler[]'}) eq 'ARRAY')) {
		$svc_ws->write("C$i", "scheduler(s):", $label_format); $svc_ws->write("D$i", join("\n", @{$lynis_report_data{"scheduler[]"}})); $i++;
	} else {
		$svc_ws->write("C$i", "scheduler(s):", $label_format); $svc_ws->write("D$i", $lynis_report_data{"scheduler[]"}); $i++;
	}
	$svc_ws->write("C$i", "service manager:", $label_format); $svc_ws->write("D$i", $lynis_report_data{"service_manager"}); $i++;
	$svc_ws->write("C$i", "smtp daemon:", $label_format); $svc_ws->write("D$i", $lynis_report_data{"smtp_daemon"}); $i++;
	$svc_ws->write("C$i", "systemctl exit code:", $label_format); $svc_ws->write("D$i", $lynis_report_data{'systemctl_exit_code'}); $i = 3;
	$svc_ws->write("E$i", "syslog daemon present:", $label_format); $svc_ws->write("F$i", uc($to_bool{$lynis_report_data{'syslog_daemon_present'}})); $i++;
	$svc_ws->write("E$i", "syslog daemon(s):", $label_format); $svc_ws->write("F$i", join("\n", @{$lynis_report_data{'syslog_daemon[]'}})); $i++;
	#if ($i > $i_hold) { $i_hold = $i; } # $i should be 11, so this should never actually be true
	#$i = $i_hold; $i++; # reset to 13 and add 1 (14)
	# Just manually reset to 14, since we added the new column.
	$i = 14;
	#$i += 2;
	$svc_ws->merge_range("A$i:D$i", "ntp detail", $spanhead_format); $i++;
	$svc_ws->write("A$i", "ntp config found:", $label_format); $svc_ws->write("B$i", uc($to_bool{$lynis_report_data{'ntp_config_found'}}));
	$svc_ws->write("C$i", 'ntp config file:', $label_format); $svc_ws->write("D$i", $lynis_report_data{'ntp_config_file'}); $i++;
	$svc_ws->write("A$i", 'ntp version:', $label_format); $svc_ws->write("B$i", $lynis_report_data{'ntp_version'});
	$svc_ws->write("C$i", 'ntp unreliable peers:', $label_format); 
	if ((exists($lynis_report_data{'ntp_unrealiable_peer[]'})) and (ref($lynis_report_data{'ntp_unreliable_peer[]'}) eq 'ARRAY')) {
		$svc_ws->write("D$i", join("\n", @{$lynis_report_data{'ntp_unrealible_peer[]'}}));
	} else {
		$svc_ws->write("D$i", $lynis_report_data{'ntp_unreliable_peer[]'});
	} 
	$i++;
	$svc_ws->write("A$i", "ntp config type:", $label_format); 
	if ($lynis_report_data{'ntp_config_type_startup'}) {
		$svc_ws->write("B$i", "startup");
	} elsif ($lynis_report_data{'ntp_config_type_eventbased'}) {
		$svc_ws->write("B$i", "eventbased");
	} elsif ($lynis_report_data{'ntp_config_type_daemon'}) {
		$svc_ws->write("B$i", "daemon");
	} elsif ($lynis_report_data{'ntp_config_type_scheduled'}) {
		$svc_ws->write("B$i", "scheduled");
	} else {
		$svc_ws->write("B$i", "unrecognized");
	}

	$i += 2;
	$svc_ws->merge_range("A$i:D$i", "Apache detail", $spanhead_format); $i++;
	$svc_ws->write("A$i", 'apache_version:', $label_format); $svc_ws->write("B$i", $lynis_report_data{'apache_version'});
	$svc_ws->write("C$i", 'apache modules:', $label_format); 
	if (ref($lynis_report_data{'apache_module[]'}) eq 'ARRAY') {
		$svc_ws->write("D$i", join("\r\n", @{$lynis_report_data{'apache_module[]'}}), $list_format); $i++;
	} else {
		$svc_ws->write("D$i", $lynis_report_data{'apache_module[]'}, $list_format); $i++;
	}

	$i++;
	$svc_ws->merge_range("A$i:D$i", "nginx detail", $spanhead_format); $i++;
	$svc_ws->write("A$i", 'nginx main config file:', $label_format); $svc_ws->write("B$i", $lynis_report_data{'nginx_main_conf_file'}); 
	if (ref($lynis_report_data{'nginx_sub_conf_file'}) eq 'ARRAY') {
		$svc_ws->write("C$i", 'nginx sub config files:', $label_format); $svc_ws->write("D$i", join("\r\n", @{$lynis_report_data{'nginx_sub_conf_file[]'}}), $list_format); $i++;
	} else {
		$svc_ws->write("C$i", 'nginx sub config files:', $label_format); $svc_ws->write("D$i", $lynis_report_data{'nginx_sub_conf_file[]'}, $list_format); $i++;
	}
	if (ref($lynis_report_data{'log_file'}) eq 'ARRAY') {
		$svc_ws->write("A$i", 'nginx log files:', $label_format); $svc_ws->write("B$i", join("\r\n", @{$lynis_report_data{'log_file'}}), $list_format);
	} else {
		$svc_ws->write("A$i", 'nginx log files:', $label_format); $svc_ws->write("B$i", $lynis_report_data{'log_file'}, $list_format);
	}
	if (ref($lynis_report_data{'ssl_tls_protocol_enabled[]'}) eq 'ARRAY') {
		$svc_ws->write("C$i", 'SSL/TLS protocols enabled:', $label_format); $svc_ws->write("D$i", join("\r\n", @{$lynis_report_data{'ssl_tls_protocol_enabled[]'}}), $list_format); $i++;
	} else {
		$svc_ws->write("C$i", 'SSL/TLS protocols enabled:', $label_format); $svc_ws->write("D$i", $lynis_report_data{'ssl_tls_protocol_enabled[]'}, $list_format); $i++;
	}
	$svc_ws->write("A$i", 'nginx config options:', $label_format); 
	if (ref($lynis_report_data{'nginx_config_option[]'}) eq 'ARRAY') {
		foreach my $opt ( @{$lynis_report_data{'nginx_config_option[]'}} ) {
			$svc_ws->write("B$i", $opt); $i++;
		}
	} else {
		$svc_ws->write("B$i", $lynis_report_data{'nginx_config_option[]'}); $i++;
	}
		

	$i++; # give it a row for space
	$svc_ws->merge_range("A$i:D$i", "systemd detail", $spanhead_format); $i++;
	$svc_ws->write("A$i", "systemd enabled:", $label_format); $svc_ws->write("B$i", uc($to_bool{$lynis_report_data{'systemd'}}));
	$svc_ws->write("C$i", "systemd status:", $label_format); $svc_ws->write("D$i", $lynis_report_data{'systemd_status'}); $i++;
	$svc_ws->write("A$i", "systemd built-in components:", $label_format); $svc_ws->merge_range("B$i:D$i", $lynis_report_data{'systemd_builtin_components'}, $merge_format); $i++;
	$svc_ws->write("A$i", "systemd version:", $label_format); $svc_ws->write("B$i", $lynis_report_data{'systemd_version'}); $i++;
	$i_hold = $i; # reset the ($i_hold) bar.  All lists below start at his row level
	$svc_ws->write("A$i", "running services:", $subsub_format); $i++;
	if ((exists($lynis_report_data{'running_service[]'})) and (ref($lynis_report_data{'running_service[]'}) eq 'ARRAY')) {
		foreach my $svc ( sort @{$lynis_report_data{'running_service[]'}} ) {
			$svc_ws->write("A$i", $svc); $i++;
		}
	} else {
		warn colored("running_service[] array not found or not an array!", "yellow");
		print STDERR color("yellow");
		print STDERR Dumper($lynis_report_data{'running_service[]'});
		print STDERR color('reset');
	}
	$i = $i_hold;
	$svc_ws->write("B$i", "systemd services not found:", $subsub_format); $i++;
	if ((exists($lynis_report_data{'systemd_service_not_found[]'})) and (ref($lynis_report_data{'systemd_service_not_found[]'}) eq 'ARRAY')) {
		foreach my $svc ( sort @{$lynis_report_data{'systemd_service_not_found[]'}} ) {
			$svc_ws->write("B$i", $svc); $i++;
		}
	} else {
		warn colored("systemd_service_not_found[] array not found or not an array!", "yellow");
		print STDERR color("yellow");
		print STDERR Dumper($lynis_report_data{'systemd_service_not_found[]'});
		print STDERR color('reset');
	}
	$i = $i_hold;
	$svc_ws->merge_range("C$i:D$i", "systemd unit files:", $subsub_format); $i++;
	$svc_ws->write("C$i", "unit", $label_format); $svc_ws->write("D$i", "status", $label_format); $i++;
	if (ref($lynis_report_data{'systemd_unit_file[]'}) eq 'ARRAY') {
		foreach my $svc ( sort @{$lynis_report_data{'systemd_unit_file[]'}} ) {
			chomp($svc);
			my ($s, $st, @j) = split(/\|/, $svc);
			$svc_ws->write("C$i", $s); $svc_ws->write("D$i", $st); $i++;
		}
	} else {
		warn colored("systemd_unit_file[] not an array!", "yellow");
		print STDERR color("yellow");
		print STDERR Dumper($lynis_report_data{'systemd_unit_file[]'});
		print STDERR color('reset');
	}
	$i = $i_hold;
	$svc_ws->write("E$i", "systemd unit not found:", $subsub_format); $i++;
	if (ref($lynis_report_data{'systemd_unit_not_found[]'}) eq 'ARRAY') {
		foreach my $svc ( sort @{$lynis_report_data{'systemd_unit_not_found[]'}} ) {
			$svc_ws->write("E$i", $svc); $i++;
		}
	} else {
		warn colored("systemd_unit_not_found[] not an array!", "yellow");
		print STDERR color("yellow");
		print STDERR Dumper($lynis_report_data{'systemd_unit_not_found[]'});
		print STDERR color('reset');
	}
	$i++;

	### package info
	my $pkg_ws = $wb->add_worksheet('package info');
	$pkg_ws->write('A1', "package info:", $title_format);
	$pkg_ws->write('A2', "number of packages installed:", $label_format); $pkg_ws->write('B2', $lynis_report_data{'installed_packages'}); $pkg_ws->write('C2', 'number of binaries found:', $label_format); $pkg_ws->write('D2', $lynis_report_data{'binaries_count'});
	$pkg_ws->merge_range('A4:D4', 'installed packages:', $subsub_format);
	#$pkg_ws->merge_range('A5:B5', 'name', $label_format); $pkg_ws->merge_range('C5:D5', 'version', $label_format);
	$i = 5;
	foreach my $p ( sort @{$lynis_report_data{'installed_packages_array'}} ) {
		chomp($p);
		#my ($name, $ver) = split(/(?:\,|\-)/, $p);
		#$pkg_ws->merge_range("A$i:B$i", $name, $merge_format); $pkg_ws->merge_range("C$i:D$i", $ver, $merge_format);
		$pkg_ws->merge_range("A$i:D$i", $p, $merge_format);
		$i++;
	}

	### Handled indeces for Excel format.
	my @indexes = qw( lynis_version lynis_tests_done license_key report_version test_category test_group installed_packages binaries_count installed_packages_array report_datetime_start report_datetime_end hostid hostid2 hostname domainname resolv_conf_domain resolv_conf_search_domain[] os os_fullname os_version framework_grsecurity framework_selinux memory_size memory_units cpu_pae cpu_nx linux_version vm uptime_in_seconds uptime_in_days locate_db available_shell[] binary_paths open_empty_log_file[] os_kernel_version os_kernel_version_full file_integrity_tool boot_uefi_booted password_max_other_credit scheduler[] ids_ips_tooling[] malware_scanner_installed redis_running auditor journal_disk_size journal_coredumps_lastday journal_oldest_bootdate journal_contais_errors jounal_bootlogs );
	my @idx2 = qw( cronjob[] log_rotation_tool log_directory[] log_rotation_config_found network_ipv4_address[] network_ipv6_address[] network_interface[] ipv6_mode ipv6_only warning[] suggestion[] network_listen_port[] usb_authorized_default_device[] network_mac_address[] default_gateway[] os_name lynis_update_available hardening_index plugin_directory plugins_enabled notebook open_logfile[] report_version_major report_version_minor valid_certificate[] min_password_class home_directory[] name_cache_used automation_tool_running[] real_user[] ntp_config_type_startup ntp_config_type_eventbased ntp_config_type_daemon ntp_config_type_scheduled ntp_version ntp_unreliable_peer[] ntp_config_file[] ntp_config_found redis_running linux_kernel_io_scheduler[] finish journal_meta_data );
	my @idx3 = qw( firewall_installed firewall_software[] firewall_empty_ruleset firewall_active package_audit_tool_found package_audit_tool vulnerable_packages_found package_manager[] authentication_two_factor_enabled authentication_two_factor_required ldap_oam_enabled ldap_auth_enabled minimum_password_length password_max_days password_min_days max_password_retry pam_cracklib password_strength_tested auth_failed_logins_logged password_max_u_credit password_max_l_credit password_max_o_credit ldap_pam_enabled running_service[] pam_module[] nameserver[] password_max_digital_credit massword_max_other_credit swap_partition[] linux_kernel_io_scheduler firewall_software journal_bootlogs linux_config_file linux_auditd_running lvm_volume_group[] lvm_volume[] filesystems_ext[] manual[] );
	my @idx4 = qw( compiler_installed compiler[] ids_ips_tooling file_integrity_tool_installed file_integrity_tool[] automation_tool_present automation_tool_installed[] malware_scanner installed malware_scanner[] fail2ban_config fail2ban_enabled_service[] loaded_kernel_module[] linux_default_runlevel boot_service_tool boot_urfi_booted boot_uefi_booted_secure boot_service[] linux_kernel_scheduler[] linux_amount_of_kernels linux_kernel_type linux_kernel_release linux_kernel_version os_kernel_version_full systemd_service_not_found[] systemd_unit_file[] systemd_unit_not_found[] ssh_daemon_running postgresql_running mysql_running audit_daemon_running crond_running arpwatch_running ntp_daemon_running nginx_running dhcp_client_running ntp_daemon printing_daemon pop3_daemon smtp_daemon imap_daemon );
	my @idx5 = qw( session_timeout_enabled details[] deleted_file[] file_systems_ext[] journal_contains_errors vulnerable_package[] boot_loader systemd systemd_status systemd_builtin_components service_manager systemd_version running_service_tool systemctl_exit_code plugin_firewall_iptables_list systemctl_exit_code plugin_processes_allprocesses vmtype plugin_enabled_phase1[] syslog_daemon_present syslog_daemon[] valid_certificate[] certificate[] certificates apparmor_enabled apparmor_policy_loaded pam_auth_brute_force_protection_module[] authentication_brute_force_protection container pam_pwquality localhost-mapped-to apache_version apache_module[] expired_certificate[] nginx_main_conf_file nginx_sub_conf_file[] log_file ssl_tls_protocol_enabled nginx_config[] ssl_tls_protocol_enabled[] nginx_config_option[] );
	push @indexes, @idx2, @idx3, @idx4, @idx5;
	foreach my $idx ( sort @indexes ) {
		delete($lynis_report_data{$idx});
	}
	### unknown tab
	### capture any remaining fields that we haven't handled yet.
	my $unk_ws = $wb->add_worksheet('unknown fields');
	$i = 1;
	foreach my $k ( sort keys %lynis_report_data ) {
		$unk_ws->write("A$i", $k, $label_format); $unk_ws->write("B$i", $lynis_report_data{$k}); $i++;
	}

} else {
	open OUT, ">$htmldoc" or die colored("There was a problem opening the output file ($htmldoc): $!", "bold red");
	print OUT <<END;
<!DOCTYPE HTML>
<html lang="en">
	<head>
		<title>lynis report</title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<style type="text/css">
			html,body {color: #fff; background-color: #000;}
			h3#exceptions {color: #ff0000;}
			div#content_section {margin: 0 10% 0 10%;}
			div.content_subsection {margin: 0 5% 0 5%;}
			div.collapsable {display:none;}
			div#footer {width:60%;margin:0 auto 0 20%;}
			select {background:transparent;color:#fff;}
			table {border-collapse:collapse;border:1px solid gray;}
			table.list {border-collapse:collapse;border:none;}
			table.list td,th {border-collapse:collapse;border:none;}
			table#lynis_plugins_table {width:100%;}
			table#scoreauditor {border-collapse:collapse;border:none;width:90%;}
			td {padding:2px 5px 2px 5px;vertical-align:top;border:1px solid gray;}
			td.field_label {font-size:1.1em;font-weight:bold;color:#555;}
			td.good {background-color: #006400; color: #fff; font-weight: bold;}
			td.fair {background-color: #ffd700; color: #000; font-weight: bold;}
			td.poor {background-color: #ffa500; color: #000; font-weight: bold;}
			td.dismal {background-color: #ff0000; color: #000; font-weight: bold;}
			td.tf_bad {background-color:#ff0000; color: #000; font-weight: bold;}
			td.tf_good {background-color: #006400; color: #fff; font-weight: bold;}
			td#score {vertical-align:top;text-align:left;}
			td#auditor {vertical-align:top;text-align:right;}
			span.title_shrink {font-size: 75%;}
			a:link#github_link {color: #fff;}
			a:visited#github_link {color: #acacac;}
			a:hover#github_link {color: #0000ff;}
			a:active#github_link {color:#000;}
			a:link {color: #fff;}
			a:visited {color: #555;}
			a:hover {color: #0000ff;}
			a:active {color:#000;}
		</style>
		<script type="text/javascript">
			function toggle(link,content) {
				var ele = document.getElementById(content);
				var text = document.getElementById(link);
				if (ele.style.display == "block" ) {
					ele.style.display = "none";
					text.innerHTML = "&gt;&nbsp;show&nbsp;&lt;";
				} else {
					ele.style.display = "block";
					text.innerHTML = "&lt;&nbsp;hide&nbsp;&gt;";
				}
			}
		</script>
	</head>
	<body>
		<div id="content_section">
			<h1>lynis Asset Report</h1>
			<h2><span class="title_shrink">created by</span> <a id="github_link" href="http://github.com/d4t4king/lynis_report" target="_blank">lynis_report</a></h2>
			<table>
				<tr>
					<td><a href="#lynis_info">lynis info</a></td><td><a href="#host_info">host info</a></td>
					<td><a href="#network_info">network info</a></td><td><a href="#security_info">security Info</a></td>
					<td><a href="#boot_info">boot info</a></td><td><a href="#kernel_info">kernel info</a></td>
				</tr>
				<tr>
					<td><a href="#filesystem_info">filesystem/journalling info</a></td><td><a href="#service_info">service info</a></td>
					<td><a href="#installed_packages">installed packages</a></td><td></td>
					<td></td><td></td>
				</tr>
			</table>
			<hr />
			<h3>host findings:</h3>
			<table class="list" id="scoreauditor"><tr><td id="score"><table><tr><td>hardening index:</td>
END

	given ($lynis_report_data{'hardening_index'}) {
		when (($lynis_report_data{'hardening_index'} < 100) and ($lynis_report_data{'hardening_index'} > 90)) {
			# green
			print OUT "\t\t\t\t<td class=\"good\">$lynis_report_data{'hardening_index'}</td>";
		}
		when (($lynis_report_data{'hardening_index'} <= 90) and ($lynis_report_data{'hardening_index'} > 80)) {
			# yellow
			print OUT "\t\t\t\t<td class=\"fair\">$lynis_report_data{'hardening_index'}</td>";
		}
		when (($lynis_report_data{'hardening_index'} <= 80) and ($lynis_report_data{'hardening_index'} > 65)) {
			# orange
			print OUT "\t\t\t\t<td class=\"poor\">$lynis_report_data{'hardening_index'}</td>";
		}
		when ($lynis_report_data{'hardening_index'} <= 65) {
			# red
			print OUT "\t\t\t\t<td class=\"dismal\">$lynis_report_data{'hardening_index'}</td>";
		}
		default { 
			# error
		}
	}

	print OUT "\t\t\t</tr></table></td><td><table><tr><td id=\"auditor\">Auditor:</td><td>$lynis_report_data{'auditor'}</td></tr></table></td></tr></table>\n";
	# handle "exception events"
	if (exists($lynis_report_data{'exception_event[]'})) {
		print OUT "<h3 id=\"exceptions\">exceptions!</h3>\n";
		print OUT "<div class=\"content_subsection\">\n";
		print OUT "<div> There were exceptions found on this system.  This means that there is something drastically wrong with the system OR lynis doesn't quite know how to handle what it found.</div><br />\n";
		if (ref($lynis_report_data{'exception_event[]'}) eq 'ARRAY') {
			print OUT "<table border=\"1\">\n";
			foreach my $exp ( @{$lynis_report_data{'exception_event[]'}} ) {
				print OUT "<tr><td>$exp</td></tr>\n";
			}
			print OUT "</table>\n</div>\n";
		} else {
			print OUT "<table border=\"1\"><tr><td>$lynis_report_data{'exception_event[]'}</td></tr></table>\n";
		}
	}

	# warnings
	if (!exists($lynis_report_data{'warning[]'})) {
		print OUT "<h4>warnings (0):</h4>\n";
	} else {
		print OUT "<h4>warnings (".scalar(@{$lynis_report_data{'warning[]'}})."):</h4>\n";
	}
	print OUT <<END;
			<div class="content_subsection">
				<table>
					<tr><td>Warning ID</td><td>Description</td><td>Severity</td><td>F4</td></tr>
END
	if (exists($lynis_report_data{'warning[]'})) {
		if (ref($lynis_report_data{'warning[]'}) eq 'ARRAY') {
			if (${$lynis_report_data{'warning[]'}}[0] =~ /\|/) { 									# more than one
				foreach my $warn ( sort @{$lynis_report_data{'warning[]'}} ) {
					my ($warn_id,$warn_desc,$warn_sev,$warn_f4) = split(/\|/, $warn);
					print OUT "\t\t\t\t\t<tr><td>$warn_id</td><td>$warn_desc</td><td>$to_long_severity{$warn_sev}</td><td>$warn_f4</td></tr>\n";
				}
			} elsif (${$lynis_report_data{'warning[]'}}[0] =~ /[A-Z]{4}\-\d{4}/) {					# one warning
				print colored(Dumper(\@{$lynis_report_data{'warning[]'}})."\n", "green") if ($verbose);
				my $warn_id = ${$lynis_report_data{'warning[]'}}[0];
				my $warn_desc = ${$lynis_report_data{'warning[]'}}[1];
				my $warn_sev = ${$lynis_report_data{'warning[]'}}[2];
				my $warn_f4 = ${$lynis_report_data{'warning[]'}}[3];
				print OUT "\t\t\t\t\t<tr><td>$warn_id</td><td>$warn_desc</td><td>$to_long_severity{$warn_sev}</td><td>$warn_f4</td></tr>\n";
			} else {
				die colored("Unexpected ARRAY format!\n".Dumper(\@{$lynis_report_data{'warning[]'}}), "bold red");
			}
		} else {
			die colored("warning[] not ARRAY ref: ".ref($lynis_report_data{'warning[]'}), "bold red");
		}
	}
	print OUT <<END;
				</table>
			</div>
END
	if ((ref($lynis_report_data{'suggestion[]'}) eq 'ARRAY') and 
		(${$lynis_report_data{'suggestion[]'}}[0] =~ /\|/)) {
			print OUT "\t\t\t<h4>suggestions (".scalar(@{$lynis_report_data{'suggestion[]'}})."):</h4>\n";
	} else {
		print OUT "\t\t\t<h4>suggestions (0):</h4>\n";
	}
	print OUT <<END;
			<div class="content_subsection">
				<table>
					<tr><td>Suggestion ID</td><td>Description</td><td>Severity</td><td>F4</td></tr>
END
	if ((ref($lynis_report_data{'suggestion[]'}) eq 'ARRAY') and
		(${$lynis_report_data{'suggestion[]'}}[0] =~ /\|/)) {
		foreach my $sug ( sort @{$lynis_report_data{'suggestion[]'}} ) {
			my ($sug_id,$sug_desc,$sug_sev,$sug_f4,$sug_f5) = split(/\|/, $sug);
			if ($sug_desc eq 'Consider hardening SSH configuration') {
				$sug_desc .= ": $sug_sev"; $sug_sev = '-';
			}
			print OUT "\t\t\t\t\t<tr><td>$sug_id</td>";
			print OUT "<td>$sug_desc</td>";
			print OUT "<td>".($sug_sev ? $sug_sev : "&nbsp;")."</td>";
			print OUT "<td>".($sug_f4 ? $sug_f4 : "&nbsp;")."</td></tr>\n";
		}
	}
	print OUT <<END;
				</table>
			<h4>manual checks:</h4>
			<ul>
END
	if ((exists($lynis_report_data{'manual[]'})) and (scalar(@{$lynis_report_data{'manual[]'}}) > 0)) {
		foreach my $man ( sort @{$lynis_report_data{'manual[]'}} ) {
			#print Dumper($man);
			chomp($man);
			print OUT "\t\t\t\t\t<li>$man</li>\n";
		}
	}
	print OUT <<END;
			</ul><br />
END
	if ((exists($lynis_report_data{'deleted_file[]'})) and ($lynis_report_data{'deleted_file[]'} ne "")) {
		if (ref($lynis_report_data{'deleted_file[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t<h5>deleted files (".scalar(@{$lynis_report_data{'deleted_file[]'}})."):</h5>\n";
			if (scalar(@{$lynis_report_data{'deleted_file[]'}}) < 10) {
				print OUT "\t\t\t\t<select size=\"".scalar(@{$lynis_report_data{'deleted_file[]'}})."\" name=\"lbDeletedFiles\">\n";
			} else {
				print OUT "\t\t\t\t<select size=\"10\" name=\"lbDeletedFiles\">\n";
			}
			foreach my $f ( @{$lynis_report_data{'deleted_file[]'}} ) { print OUT "\t\t\t\t\t<option>$f\n"; }
		} else {
			if (($verbose) and ($verbose > 1)) {
				warn colored("Deleted files object not an array! ", "yellow");
				print Dumper($lynis_report_data{'delete_file[]'});
			}
		}
	}
	print OUT "\t\t\t\t</select><br />\n";
	if ((exists($lynis_report_data{'vulnerable_package[]'})) and ($lynis_report_data{'vulnerable_package[]'} ne "")) {
		if (ref($lynis_report_data{'vulnerable_package[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t<h4>Vulnerable packages (".scalar(@{$lynis_report_data{'vulnerable_package[]'}})."):\n";
			print OUT "\t\t\t\t<ul>\n";
			foreach my $p ( @{$lynis_report_data{'vulnerable_package[]'}} ) { print OUT "\t\t\t\t\t<li>$p</li>\n"; }
			print OUT "\t\t\t\t</ul><br />\n";
		} else {
			if ((($verbose) and ($verbose > 1)) or ($debug)) {
				warn colored("Vulnerable package object not an array!", "yellow");
				print color('yellow'); print Dumper($lynis_report_data{'vulnerable_package[]'}); print color('reset');
			}
		}
	}
	# It's easier to move stuff around if there is one cell (or cell group) per libe for the tables.  Maybe this
	# isn't ideal HTML writing, but it makes sense when writing the tool.
	$lynis_report_data{'lynis_update_available'} = 0 if ((!defined($lynis_report_data{'lynis_update_available'})) or ($lynis_report_data{'lynis_update_available'} eq ""));
	print OUT <<END;
			</div>
			<hr />
<!-- 
###############################
### LYNIS INFO
###############################
-->
			<h3><a id="lynis_info">lynis info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
END
	print OUT "\t\t\t\t\t<td class=\"field_label\">lynis version:</td><td>$lynis_report_data{'lynis_version'}</td>\n";
	print OUT "\t\t\t\t\t<td class=\"field_label\">lynis tests done:</td><td>$lynis_report_data{'lynis_tests_done'}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	if (($lynis_report_data{'lynis_update_available'} == 0) or ($lynis_report_data{'lynis_update_available'} == 1)) {
		print OUT "\t\t\t\t\t<td class=\"field_label\">lynis update available:</td><td>$to_bool{$lynis_report_data{'lynis_update_available'}}</td>\n";
	} elsif ($lynis_report_data{'lynis_update_available'} == -1) {
		print OUT "\t\t\t\t\t<td class=\"field_label\">lynis update available:</td><td>N/A - There was an unexpected error trying to retrieve update status.</td>\n";
	} else {
		warn colored("Unexpected result from lynis update available check!", "yellow");
		print Dumper($lynis_report_data{'lynis_update_available'});
	}
	print OUT "\n\n\n\n\n\n<td class=\"field_label\">license key:</td><td>$lynis_report_data{'license_key'}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
						<td colspan="2" class="field_label">report version:</td><td colspan="2">$lynis_report_data{'report_version_major'}.$lynis_report_data{'report_version_minor'}</td>
					</tr>
					<tr>
						<td class="field_label">test category:</td><td>$lynis_report_data{'test_category'}</td>
						<td class="field_label">test group:</td><td>$lynis_report_data{'test_group'}</td>
					</tr>
					<tr>
						<td class="field_label">number of plugins enabled:</td><td>$lynis_report_data{'plugins_enabled'}</td>
						<td class="field_label">plugin directory:</td><td>$lynis_report_data{'plugin_directory'}</td>
					</tr>
					<tr>
END

	print OUT "\t\t\t\t\t\t<td class=\"field_label\">phase 1 plugins enabled:</td><td colspan=\"3\">\n";
	print OUT "\t\t\t\t\t\t\t<table id=\"lynis_plugins_table\">\n";
	if (exists($lynis_report_data{'plugin_enabled_phase1[]'})) {
		if (ref($lynis_report_data{'plugin_enabled_phase1[]'}) eq 'ARRAY') {
			foreach my $plug ( sort @{$lynis_report_data{'plugin_enabled_phase1[]'}} ) { 
				my ($n,$v) = split(/\|/, $plug);
				if ((!defined($v)) or ($v eq "")) { $v = "AAAAAAAA"; }
				print OUT "\t\t\t\t\t\t\t\t<tr><td>name:</td><td>$n</td><td>version:</td><td>$v</td></tr>\n";
			}
		}
	}
	print OUT "\t\t\t\t\t\t\t</table>\n";
	print OUT "\t\t\t\t\t\t</td>\n";
	print OUT <<END;
					</tr>
					<tr>
						<td class="field_label">report start time:</td><td>$lynis_report_data{'report_datetime_start'}</td><td>report end time:</td><td>$lynis_report_data{'report_datetime_end'}</td>
					</tr>
					<tr><td class="field_label">hostid:</td><td colspan="3">$lynis_report_data{'hostid'}</td></tr>
					<tr><td class="field_label">hostid:</td><td colspan="3">$lynis_report_data{'hostid2'}</td></tr>
END
	if (ref($lynis_report_data{'plugin_firewall_iptables_list'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t<tr><td class=\"field_label\">Plugin-firewall iptables list:</td><td colspan=\"3\">".join("<br />\n", @{$lynis_report_data{'plugin_firewall_iptables_list'}})."</td></tr>\n";
	}
	print OUT "\t\t\t\t</table>\n";
	if ((exists($lynis_report_data{'plugin_processes_allprocesses'})) and ($lynis_report_data{'plugin_processes_allprocesses'} ne "")) {
		print OUT "\t\t\t\t<h5>Plugin-processes: discovered processes:</h5>\n";
		if (ref($lynis_report_data{'plugin_processes_allprocesses'}) eq 'ARRAY') {
			if (scalar(@{$lynis_report_data{'plugin_processes_allprocesses'}}) < 10) {
				print OUT "\t\t\t\t\t\t<select size=\"".scalar(@{$lynis_report_data{'plugin_processes_allprocesses'}})."\" name=\"lbPluginProcessesAllProcesses\" >\n";
			} else {
				print OUT "\t\t\t\t\t<select size=\"10\" name=\"lbPluginProcessesAllProcesses\" >\n";
			}
			foreach my $p ( sort @{$lynis_report_data{'plugin_processes_allprocesses'}} ) { print OUT "\t\t\t\t\t\t<option>$p\n"; }
			print OUT "\t\t\t\t\t</select>\n";
		} else {
			if ((($verbose) and ($verbose > 1)) or ($debug)) {
				warn colored("plugin processess allprocesses object not an array! ", "yellow");
				print Dumper($lynis_report_data{'plugin_processes_allprocesses'});
			}
		}
	}
###########################
### HOST INFO
###########################
	print OUT <<END;
			</div>
			<hr />
			<h3><a id="host_info">host info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td class="field_label">hostname:</td><td>$lynis_report_data{'hostname'}</td>
						<td class="field_label">domainname:</td><td>$lynis_report_data{'domainname'}</td>
END
	if ((defined($lynis_report_data{'resolv_conf_domain'})) and ($lynis_report_data{'resolv_conf_domain'} ne "")) {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">resolv.conf domain:</td><td>$lynis_report_data{'resolv_conf_domain'}</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">resolv.conf domain:</td><td>&nbsp;</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
						<td class="field_label">os:</td><td>$lynis_report_data{'os'}</td>
						<td class="field_label">os fullname:</td><td>$lynis_report_data{'os_fullname'}</td>
						<td class="field_label">os_version:</td><td>$lynis_report_data{'os_version'}</td>
					</tr>
					<tr>
						<td class="field_label">GRSecurity:</td><td>$to_bool{$lynis_report_data{'framework_grsecurity'}}</td>
						<td class="field_label">SELinux:</td><td>$to_bool{$lynis_report_data{'framework_selinux'}}</td>
						<td class="field_label">memory:</td><td>$lynis_report_data{'memory_size'} $lynis_report_data{'memory_units'}</td>
					</tr>
					<tr>
						<td class="field_label">linux version:</td><td>$lynis_report_data{'linux_version'}</td>
						<td class="field_label">pae enabled:</td><td>$to_bool{$lynis_report_data{'cpu_pae'}}</td>
						<td class="field_label">nx enabled:</td><td>$to_bool{$lynis_report_data{'cpu_nx'}}</td>
					</tr>
					<tr>
END
	if (exists($lynis_report_data{'available_shell[]'})) {
		if (ref($lynis_report_data{'available_shell[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t\t<td class=\"field_label\">Available shells:</td><td>".join("<br />\n", @{$lynis_report_data{'available_shell[]'}})."</td>\n";
		} else {
			print OUT "\t\t\t\t\t\t<td class=\"field_label\">Available shells:</td><td>$lynis_report_data{'available_shell[]'}</td>\n";
		}
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">Available shells:</td><td>&nbsp;</td>\n";
	}
	$lynis_report_data{'locate_db'} = "&nbsp;" if ((!defined($lynis_report_data{'locate_db'})) or ($lynis_report_data{'locate_db'} eq ""));
	#print STDERR colored($lynis_report_data{'vm'}."\n", "bold magenta");
	$lynis_report_data{'vm'} = 0 if ((!defined($lynis_report_data{'vm'})) or ($lynis_report_data{'vm'} eq ""));
	#print STDERR colored($lynis_report_data{'vm'}."\n", "bold magenta");
	print OUT "\t\t\t\t\t<td class=\"field_label\">locate db:</td><td>$lynis_report_data{'locate_db'}</td>\n";
	print OUT "\t\t\t\t\t<td class=\"field_label\">uptime (days):</td><td>$lynis_report_data{'uptime_in_days'}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
						<td class="field_label">vm:</td><td>$vm_mode{$lynis_report_data{'vm'}}</td>
END
	if ((defined($lynis_report_data{'vmtype'})) and ($lynis_report_data{'vmtype'} ne "")) {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">vm_type:</td><td>$lynis_report_data{'vmtype'}</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">vm_type:</td><td>&nbsp;</td>\n";
	}
	print OUT <<END;
						<td class="field_label">uptime (secs):</td><td>$lynis_report_data{'uptime_in_seconds'}</td>
					</tr>
END
	print OUT "<tr><td class=\"field_label\">is notebook/laptop:</td><td colspan=\"2\">$to_bool{$lynis_report_data{'notebook'}}</td>";
	print OUT "<td class=\"field_label\">is Docker container:</td><td colspan=\"2\">$to_bool{$lynis_report_data{'container'}}</td></tr>\n";
	print OUT <<END;
					<tr>
						<td class="field_label">binary paths:</td><td colspan="2">$lynis_report_data{'binary_paths'}</td>
END
	if (ref($lynis_report_data{'valid_certificate[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">valid certificates:</td><td colspan=\"2\">".join("<br />\n",@{$lynis_report_data{'valid_certificate[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">valid certificates:</td><td colspan=\"2\">$lynis_report_data{'valid_certificate[]'}</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
END
	if (ref($lynis_report_data{'usb_authorized_default_device[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">authorized default USB devices:</td><td colspan=\"2\">".join("<br \>\n", @{$lynis_report_data{'usb_authorized_default_device[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">authorized default USB devices:</td><td colspan=\"2\">$lynis_report_data{'usb_authorized_default_device[]'}</td>\n";
	}
	if (ref($lynis_report_data{'expired_certificate[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">expired certificates:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'expired_certificate[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">expired certificates:</td><td colspan=\"2\">$lynis_report_data{'expired_certificate[]'}</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
END
	#if ($verbose) { print colored("Contents of \$lynis_report_data\{\'certificates\'\}:\n".Dumper($lynis_report_data{'certificates'}), "yellow"); }
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">certificate count:</td><td colspan=\"2\">$lynis_report_data{'certificates'}</td>\n";
	if (ref($lynis_report_data{'certificate[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">certificates:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'certificate[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">certificates:</td><td colspan=\"2\">$lynis_report_data{'certificate[]'}</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
END
	if (exists($lynis_report_data{'compiler_world_executable[]'})) {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">world executable compiler(s):</td>";
		if (ref($lynis_report_data{'compiler_world_executable[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t\t<td colspan=\"2\">".join("<br />\n". @{$lynis_report_data{'compiler_world_executable[]'}})."</td>\n";
		} else {
			print OUT "\t\t\t\t\t\t<td colspan=\"2\">$lynis_report_data{'compiler_world_executable[]'}</td>\n";
		}
	} else {
		print OUT <<END;
						<td class="field_label"></td><td colspan="2"></td>
END
	}
	print OUT <<END;
						<td class="field_label"></td><td colspan="2"></td>
					</tr>
				</table>
				<h4>cron jobs:</h4>
END
	if (ref($lynis_report_data{'cronjob[]'}) eq "ARRAY") {
		print OUT "\t\t\t\t\t<select size=\"10\" name=\"lbCronJobs\">\n";
		foreach my $c ( @{$lynis_report_data{'cronjob[]'}} ) { 
			$c =~ s/,/\t&nbsp;/g;
			print OUT "\t\t\t\t\t\t<option>$c\n"; 
		}
		print OUT "\t\t\t\t\t</select>\n";
	}
	print OUT <<END;

				<h4>logging info:</h4>
				<table>
					<tr>
						<td class="field_label">log rotation tool:</td><td>$lynis_report_data{'log_rotation_tool'}</td>
						<td class="field_label">log rotation config found:</td><td>$to_bool{$lynis_report_data{'log_rotation_config_found'}}</td>
					</tr>
END
	
	if (ref($lynis_report_data{'syslog_daemon_present'}) eq 'ARRAY') {
		my $i = 0;
		foreach my $e ( @{$lynis_report_data{'syslog_daemon_present'}} ) { $i += $e; }
		if ($i >= 1) {
			print OUT "<tr><td  class=\"field_label\"colspan=\"2\">syslog daemon detected:</td><td colspan=\"2\">$to_bool{1}</td></tr>\n";
		} else {
			print OUT "<tr><td  class=\"field_label\"colspan=\"2\">syslog daemon detected:</td><td colspan=\"2\">$to_bool{0}</td></tr>\n";
		}
	} else {
		print OUT "<tr><td  class=\"field_label\"colspan=\"2\">syslog daemon detected:</td><td colspan=\"2\">$to_bool{$lynis_report_data{'syslog_daemon_present'}}</td></tr>\n";
	}
	print OUT <<END;
					<tr>
						<td class="field_label" colspan="2">syslog daemon(s):</td>
END
	if (ref($lynis_report_data{'syslog_daemon[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'syslog_daemon[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td colspan=\"2\">$lynis_report_data{'syslog_daemon[]'}</td>\n";
	}
	print OUT "\t\t\t\t\t</tr>\n";
	print OUT <<END;
				</table>
				<br />
				<h4>log directories:</h4>
END
	if (ref($lynis_report_data{'log_directory[]'}) eq 'ARRAY') {
		if (scalar(@{$lynis_report_data{'log_directory[]'}}) < 10) {
			print OUT "\t\t\t\t\t<select size=\"".scalar(@{$lynis_report_data{'log_directory[]'}})."\" name=\"lbLogDirectories\">\n";
		} else {
			print OUT "\t\t\t\t\t<select size=\"10\" name=\"lbLogDirectories\">\n";
		}
		foreach my $ld ( @{$lynis_report_data{'log_directory[]'}} ) { print OUT "\t\t\t\t\t\t<option>$ld\n"; }
		print OUT "\t\t\t\t\t</select>\n";
	}
	print OUT "\t\t\t\t\t<h4>open log files:</h4>\n";
	if (ref($lynis_report_data{'open_logfile[]'}) eq 'ARRAY') {
		if (scalar(@{$lynis_report_data{'open_logfile[]'}}) < 10) {
			print OUT "\t\t\t\t\t<select size=\"".scalar(@{$lynis_report_data{'open_logfile[]'}})."\" name=\"blOpenLogFiles\">\n";
		} else {
			print OUT "\t\t\t\t\t<select size=\"10\" name=\"blOpenLogFiles\">\n";
		}
		foreach my $lf ( @{$lynis_report_data{'open_logfile[]'}} ) { print OUT "\t\t\t\t\t\t<option>$lf\n"; }
		print OUT "\t\t\t\t\t</select>\n";
	}
	print OUT "\t\t\t\t<h4>open empty log files:</h4>\n";
	if (ref($lynis_report_data{'open_empty_log_file[]'}) eq 'ARRAY') {
		if (scalar(@{$lynis_report_data{'open_empty_log_file[]'}}) < 10) {
			print OUT "\t\t\t\t\t<select size=\"".scalar(@{$lynis_report_data{'open_empty_log_file[]'}})."\" name=\"blOpenEmptyLogFiles\">\n";
		} else { 
			print OUT "\t\t\t\t\t<select size=\"10\" name=\"blOpenEmptyLogFIles\">\n";
		}
		foreach my $elf ( @{$lynis_report_data{'open_empty_log_file[]'}} ) { print OUT "\t\t\t\t\t\t<option>$elf\n"; }
		print OUT "\t\t\t\t\t</select>\n";
	}
################################
### NETWORK INFO
################################
	print OUT <<END;
			</div>
			<hr />
			<h3><a id="network_info">network info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td class="field_label">IPv6 Mode:</td><td>$lynis_report_data{'ipv6_mode'}</td>
						<td class="field_label">IPv6 Only:</td><td>$to_bool{$lynis_report_data{'ipv6_only'}}</td>
					</tr>
END
	if (exists($lynis_report_data{'network_interface[]'})) {
		if (ref($lynis_report_data{'network_interface[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">network interfaces:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'network_interface[]'}})."</td></tr>\n";
		} else {
			print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">network interfaces:</td><td colspan=\"2\">$lynis_report_data{'network_interface[]'}</td></tr>\n";
		}
	} else {
		print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">network interfaces:</td><td colspan=\"2\">&nbsp;</td></tr>\n";
	}
	print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">localhost mapped to:</td><td colspan=\"2\">$lynis_report_data{'localhost-mapped-to'}</td></tr>\n";
	if (exists($lynis_report_data{'network_ipv4_address[]'})) {
		if (ref($lynis_report_data{'network_ipv4_address[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">ipv4 addresses:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'network_ipv4_address[]'}})."</td></tr>\n";
		} else {
			print OUT "\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">ipv4 addresses:</td><td colspan=\"2\">$lynis_report_data{'network_ipv4_address[]'}</td></tr>\n";
		}
	} else {
			print OUT "\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">ipv4 addresses:</td><td colspan=\"2\">&nbsp;</td></tr>\n";
	}
	if (exists($lynis_report_data{'network_ipv6_address[]'})) {
		if (ref($lynis_report_data{'network_ipv6_address[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">ipv6 addresses:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'network_ipv6_address[]'}})."</td></tr>\n";
		} else {
			print OUT "\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">ipv6 addresses:</td><td colspan=\"2\">$lynis_report_data{'network_ipv6_address[]'}</td></tr>\n";
		}
	} else {
			print OUT "\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">ipv6 addresses:</td><td colspan=\"2\">&nbsp;</td></tr>\n";
	}
	print OUT "\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">Default Gateway</td><td colspan=\"2\">$lynis_report_data{'default_gateway[]'}</td></tr>\n";
	print OUT "\t\t\t\t\t<tr>\n";
	#print STDERR "Should be ARRAY: |".ref($lynis_report_data{'network_mac_address[]'})."|\n";
	if (ref($lynis_report_data{'network_mac_address[]'}) eq "ARRAY") {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">MAC Address:</td><td>".join("<br />\n", @{$lynis_report_data{'network_mac_address[]'}})."</td>\n";
	} elsif ((defined($lynis_report_data{'network_mac_address[]'})) and ($lynis_report_data{'network_mac_address[]'} ne "")) {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">MAC Address:</td><td>$lynis_report_data{'network_mac_address[]'}</td>\n";
	} else { 
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">MAC Address:</td><td>&nbsp;</td>\n";
	}
	print OUT <<END;
						<td class="field_label">Name Cache Used:</td><td>$to_bool{$lynis_report_data{'name_cache_used'}}</td>
					</tr>
END
	if (ref($lynis_report_data{'nameserver[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">name servers:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'nameserver[]'}})."</td></tr>\n";
	} else {
		print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\" colspan=\"2\">name servers:</td><td colspan=\"2\">$lynis_report_data{'nameserver[]'}</td></tr>\n";
	}
	print OUT <<END;
					<tr>
						<td class="field_label" colspan="2">resolv.conf search domain:</td>
END
	if (ref($lynis_report_data{'resolv_conf_search_domain[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td colspan=\"2\">".join("<br />\n",@{$lynis_report_data{'resolv_conf_search_domain[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td colspan=\"2\">$lynis_report_data{'resolv_conf_search_domain[]'}</td>\n";
	}
	print OUT <<END;
					</tr>
				</table>
				<h4>Open Ports:</h4>
				<table>
					<tr><td>IP Address</td><td>Port</td><td>Protocol</td><td>Daemon/Process</td><td>???</td></tr>
END

	if (exists($lynis_report_data{'network_listen_port[]'})) {
		foreach my $obj ( sort @{$lynis_report_data{'network_listen_port[]'}} ) {
			my ($ipp,$proto,$daemon,$dunno) = split(/\|/, $obj);
			my ($ip,$port);
			if (grep(/\:/, split(//, $ipp)) > 1) {
				# must be an IPv6 address;
				my @parts = split(/\:/, $ipp);
				$port = pop(@parts);					# gets the last element of the array.  like	$parts[-1];
				$ip = join(":", @parts);				# should only be the remaining parts, which should be the ipv6 addr
			} else {
				# must be IPv4
				($ip,$port) = split(/\:/, $ipp);
			}
			print OUT "\t\t\t\t\t<tr><td>$ip</td><td>$port</td><td>$proto</td><td>$daemon</td><td>$dunno</td></tr>\n";
		}
	}
#######################################
### SECURITY INFO
#######################################
	print OUT <<END;
				</table>
			</div>
			<hr />
			<h3><a id="security_info">security info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
END
	$lynis_report_data{'firewall_installed'} = 0 if ((!defined($lynis_report_data{'firewall_installed'})) or ($lynis_report_data{'firewall_installed'} eq ''));
	print OUT "\t\t\t\t\t<td class=\"field_label\">Host Firewall Installed:</td><td>$to_bool{$lynis_report_data{'firewall_installed'}}</td>\n";
	$lynis_report_data{'firewall_software'} = "&nbsp;" if ((!defined($lynis_report_data{'firewall_software'})) or ($lynis_report_data{'firewall_software'} eq ''));
	print OUT "\t\t\t\t\t<td class=\"field_label\">Firewall Software:</td><td>$lynis_report_data{'firewall_software'}</td>\n";
	$lynis_report_data{'firewall_empty_ruleset'} = 0 if ((!defined($lynis_report_data{'firewall_empty_ruleset'})) or ($lynis_report_data{'firewall_empty_ruleset'} eq ''));
	print OUT "\t\t\t\t\t<td class=\"field_label\">Firewall Empty Ruleset:</td><td>$to_bool{$lynis_report_data{'firewall_empty_ruleset'}}</td>\n";
	$lynis_report_data{'firewall_active'} = 0 if ((!defined($lynis_report_data{'firewall_active'})) or ($lynis_report_data{'firewall_active'} eq ''));
	print OUT "\t\t\t\t\t<td class=\"field_label\">Firewall Active:</td><td>$to_bool{$lynis_report_data{'firewall_active'}}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Package Audit Tools Found:</td><td>$to_bool{$lynis_report_data{'package_audit_tool_found'}}</td>\n";
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Package Audit Tool:</td><td>$lynis_report_data{'package_audit_tool'}</td>\n";
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Vulnerable Packages Found:</td><td>$lynis_report_data{'vulnerable_packages_found'}</td>\n";
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Package Manager:</td><td>$lynis_report_data{'package_manager[]'}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	$lynis_report_data{'authentication_two_factor_enabled'} = 0 if ((!defined($lynis_report_data{'authentication_two_factor_enabled'})) or ($lynis_report_data{'authentication_two_factor_enabled'} eq ''));
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Two-Factor Authentication Enabled:</td><td>$to_bool{$lynis_report_data{'authentication_two_factor_enabled'}}</td>\n";
	$lynis_report_data{'authentication_two_factor_required'} = 0 if ((!defined($lynis_report_data{'authentication_two_factor_required'})) or ($lynis_report_data{'authentication_two_factor_required'} eq ''));
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Two-Factor Authentication Required:</td><td>$to_bool{$lynis_report_data{'authentication_two_factor_required'}}</td>\n";
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">LDAP PAM Module Enabled:</td><td>$to_bool{$lynis_report_data{'ldap_pam_enabled'}}</td>\n";
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">LDAP Auth Enabled:</td><td>$to_bool{$lynis_report_data{'ldap_auth_enabled'}}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	$lynis_report_data{'minimum_password_length'} = 0 if ((!defined($lynis_report_data{'minimum_password_length'})) or ($lynis_report_data{'minimum_password_length'} eq ''));
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Minimum Password Length:</td><td>$lynis_report_data{'minimum_password_length'}</td>\n";
	$lynis_report_data{'password_max_days'} = 0 if ((!defined($lynis_report_data{'password_max_days'})) or ($lynis_report_data{'password_max_days'} eq ''));
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Maximum Password Days:</td><td>$lynis_report_data{'password_max_days'}</td>\n";
	$lynis_report_data{'password_min_days'} = 0 if ((!defined($lynis_report_data{'password_min_days'})) or ($lynis_report_data{'password_min_days'} eq ''));
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Minimum Password Days:</td><td>$lynis_report_data{'password_min_days'}</td>\n";
	$lynis_report_data{'max_password_retry'} = 0 if ((!defined($lynis_report_data{'max_password_retry'})) or ($lynis_report_data{'max_password_retry'} eq ''));
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Maximum Password Retries:</td><td>$lynis_report_data{'max_password_retry'}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	printf OUT "\t\t\t\t\t\t<td class=\"field_label\">Password Complexity Score:</td><td>%#b</td>\n", $pass_score;
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">PAM Cracklib Found:</td><td>$to_bool{$lynis_report_data{'pam_cracklib'}}</td>\n";
	$lynis_report_data{'password_strength_tested'} = 0 if ((!defined($lynis_report_data{'password_strength_tested'})) or ($lynis_report_data{'password_strength_tested'} eq ''));
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Password Strength Tested:</td><td>$to_bool{$lynis_report_data{'password_strength_tested'}}</td>\n";
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">PAM Password Quality:</td><td>$lynis_report_data{'pam_pwquality'}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	if (exists($lynis_report_data{'file_integrity_tool_installed'})) {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">File Integrity Tool Installed:</td><td>$to_bool{$lynis_report_data{'file_integrity_tool_installed'}}</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">File Integrity Tools Installed:</td><td>false</td>\n";
	}
	if (exists($lynis_report_data{'file_integrity_tool'})) {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">File Integrity Tool:</td><td>$lynis_report_data{'file_integrity_tool'}</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">File Integrity Tool:</td><td>NA</td>\n";
	}
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Automation Tool Present:</td><td>$to_bool{$lynis_report_data{'automation_tool_present'}}</td>\n";
	if (ref($lynis_report_data{'automation_tool_running[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">Automation Tool:</td><td>".join("<br />\n", @{$lynis_report_data{'automation_tool_running[]'}})."</td>\n";
	} elsif ((defined($lynis_report_data{'automation_tool_running[]'})) and ($lynis_report_data{'automation_tool_running[]'} ne "")) {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">Automation Tool:</td><td>$lynis_report_data{'automation_tool_running[]'}</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">Automation Tool:</td><td>&nbsp;</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
						<td class="field_label">Malware Scanner Installed:</td><td>$to_bool{$lynis_report_data{'malware_scanner_installed'}}</td>
END
	if (ref($lynis_report_data{'malware_scanner[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">Malware Scanner(s):</td><td>".join("<br />\n", @{$lynis_report_data{'malware_scanner[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">Malware Scanner(s):</td><td>$lynis_report_data{'malware_scanner[]'}</td>\n";
	}
	print OUT <<END;
						<td class="field_label">compiler installed:</td><td>$to_bool{$lynis_report_data{'compiler_installed'}}</td>
END
	if (ref($lynis_report_data{'compiler[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">compilers:</td><td>".join("<br />\n", @{$lynis_report_data{'compiler[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">compilers:</td><td>$lynis_report_data{'compiler[]'}</td>\n";
	}
	print OUT <<END; 
					</tr>
					<tr>
END
	if (ref($lynis_report_data{'ids_ips_tooling[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">IDS/IPS Tooling</td><td>".join("<br />\n", @{$lynis_report_data{'ids_ips_tooling[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">IDS/IPS Tooling</td><td>$lynis_report_data{'ids_ips_tooling[]'}</td>\n";
	}
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">Failed Logins Logged:</td><td>$lynis_report_data{'auth_failed_logins_logged'}</td>\n";
	if (ref($lynis_report_data{'fail2ban_config'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">fail2ban config file(s):</td><td>".join("<br />\n", @{$lynis_report_data{'fail2ban_config'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">fail2ban config file(s):</td><td>$lynis_report_data{'fail2ban_config'}</td>\n";
	}
	if (ref($lynis_report_data{'fail2ban_enabled_service[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">fail2ban enabled service(s):</td><td>".join("<br />\n", @{$lynis_report_data{'fail2ban_enabled_service[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">fail2ban enabled service(s):</td><td>$lynis_report_data{'fail2ban_enabled_service[]'}</td>\n";
	}
	print OUT "</tr>\n";
	print OUT "<tr><td class=\"field_label\">AppArmor Enabled:</td><td>$to_bool{$lynis_report_data{'apparmor_enabled'}}</td>\n";
	print OUT "<td class=\"field_label\">AppArmor Policy Loaded:</td><td>$to_bool{$lynis_report_data{'apparmor_policy_loaded'}}</td>\n";
	print OUT "<td class=\"field_label\">SELinux Status:</td><td>$to_bool{$lynis_report_data{'selinux_status'}}</td>\n";
	print OUT "<td class=\"field_label\">SELinux mode:</td><td>$lynis_report_data{'selinux_mode'}</td></tr>\n";
	print OUT "<tr><td class=\"field_label\">Group Names Unique</td><td>$to_bool{$lynis_report_data{'auth_group_names_unique'}}</td>\n";
	print OUT "<td class=\"field_label\">Group IDs Unique</td><td>$to_bool{$lynis_report_data{'auth_group_ids_unique'}}</td>\n";
	print OUT "<td class=\"field_label\"></td><td></td>\n";
	print OUT "<td class=\"field_label\"></td><td></td></tr>\n";
	print OUT <<END;
				</table>
				<table class="list">
					<tr><td><h4>real users:</h4></td><td><h4>home directories:</h4></td></tr>
					<tr><td>
						<table class="list">
							<tr><td>name</td><td>uid</td></tr>
END
	foreach my $u ( @{$lynis_report_data{'real_user[]'}} ) { 
		my ($name,$uid) = split(/,/, $u);
		print OUT "\t\t\t\t\t\t\t<tr><td>$name</td><td>$uid</td></tr>\n"; 
	}
	print OUT "\t\t\t\t\t\t</table></td><td><select size=\"10\" name=\"lbHomeDirectories\">\n";
	foreach my $d ( @{$lynis_report_data{'home_directory[]'}} ) { print OUT "\t\t\t\t\t\t\t<option>$d\n"; }
	print OUT <<END;	
					</select></td></tr>
				</table>
				<h4>PAM Modules:</h4><a id="pamModLink" href="javascript:toggle('pamModLink', 'pamModToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="pamModToggle" style="display: none">
END
	if (ref($lynis_report_data{'pam_module[]'}) eq 'ARRAY') {
		if (scalar(@{$lynis_report_data{'pam_module[]'}}) < 25) {
			print OUT "<select id=\"pam_module[]\" size=\"".scalar(@{$lynis_report_data{'pam_module[]'}})."\">\n";
		} else {
			print OUT "<select id=\"pam_module[]\" size=\"25\">\n";
		}
		foreach my $pm ( sort @{$lynis_report_data{'pam_module[]'}} ) {
			print OUT "\t\t\t\t\t\t<option>$pm\n";
		}
		print OUT "</select>\n";
	}
	if ((!defined($lynis_report_data{'boot_service_tool'})) or ($lynis_report_data{'boot_service_tool'} eq "")) { $lynis_report_data{'boot_service_tool'} = "&nbsp;"; }
####################################
### BOOT INFO
####################################
	print OUT <<END;
					</table>
				</div>
			</div>
			<hr />
			<h3><a id="boot_info">boot info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td class="field_label">UEFI booted:</td><td>$to_bool{$lynis_report_data{'boot_uefi_booted'}}</td>
						<td class="field_label">UEFI booted secure:</td><td>$to_bool{$lynis_report_data{'boot_uefi_booted_secure'}}</td>
					</tr>
					<tr>
						<td class="field_label">default runlevel:</td><td>$lynis_report_data{'linux_default_runlevel'}</td>
						<td class="field_label">boot service tool:</td><td>$lynis_report_data{'boot_service_tool'}</td>
					</tr>
				</table>
END
	print OUT "\t\t\t\t<h4>services started at boot:</h4>\n";
	if (!defined($lynis_report_data{'boot_service[]'})) {
		print OUT "\t\t\t\t\t<ul><li>N/A - Unable to detect boot services.</li></ul>\n";
	} elsif (ref($lynis_report_data{'boot_service[]'}) eq "ARRAY") {
		if (scalar(@{$lynis_report_data{'boot_service[]'}}) < 10) {
			print OUT "\t\t\t\t\t\t<select size=\"".scalar(@{$lynis_report_data{'boot_service[]'}})."\">\n";
		} else {
			print OUT "\t\t\t\t\t\t<select size=\"10\">\n";
		}
		foreach my $svc ( @{$lynis_report_data{'boot_service[]'}} ) {
			print OUT "\t\t\t\t\t\t<option>$svc\n";
		}
		print OUT "\t\t\t\t\t</select>\n";
	} else {
		if ((($verbose) and ($verbose > 1)) or ($debug)) {
			warn colored("boot_service[] object not an array", "yellow");
			print Dumper($lynis_report_data{'boot_service[]'});
		}
	}
	$lynis_report_data{'linux_kernel_io_scheduler'} = "&nbsp;" if ((!defined($lynis_report_data{'linux_kernel_io_scheduler'})) or ($lynis_report_data{'linux_kernel_io_scheduler'} eq ""));
	$lynis_report_data{'linux_amount_of_kernels'} = "&nbsp;" if ((!defined($lynis_report_data{'linux_amount_of_kernels'})) or ($lynis_report_data{'linux_amount_of_kernels'} eq ""));
	#print Dumper($lynis_report_data{'linux_kernel_io_scheduler'});
##########################################
### KERNEL INFO
##########################################
	print OUT <<END;
			</div>
			<hr />
			<h3><a id="kernel_info">kernel info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
END
	print OUT "\t\t\t\t\t<td class=\"field_label\">kernel version:</td><td>$lynis_report_data{'linux_kernel_version'}</td>\n";
	print OUT "\t\t\t\t\t<td class=\"field_label\">full kernel version:</td><td>$lynis_report_data{'os_kernel_version_full'}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	print OUT "\t\t\t\t\t<td class=\"field_label\">kernel release version:</td><td>$lynis_report_data{'linux_kernel_release'}</td>\n";
	if (ref($lynis_report_data{'linux_kernel_io_scheduler[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t<td class=\"field_label\">kernel IO scheduler:</td><td>".join("<br />\n", @{$lynis_report_data{'linux_kernel_io_scheduler[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t<td class=\"field_label\">kernel IO scheduler:</td><td>$lynis_report_data{'linux_kernel_io_scheduler[]'}</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
END
	print OUT "\t\t\t\t\t<td class=\"field_label\">linux kernel type:</td><td>$lynis_report_data{'linux_kernel_type'}</td>\n";
	print OUT "\t\t\t\t\t<td class=\"field_label\">number of kernels available:</td><td>$lynis_report_data{'linux_amount_of_kernels'}</td>\n";
	print OUT <<END;
					</tr>
				</table>
				<h4>kernel modules loaded:</h4><a id="kernelModLink" href="javascript:toggle('kernelModLink', 'kernelModToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="kernelModToggle" style="display: none">
END
	if (ref($lynis_report_data{'loaded_kernel_module[]'}) eq 'ARRAY') {
		if (scalar(@{$lynis_report_data{'loaded_kernel_module[]'}}) < 25) {
			print OUT "\t\t\t\t\t\t<select size=\"".scalar(@{$lynis_report_data{'loaded_kernel_module[]'}})."\">\n";
		} else {
			print OUT "\t\t\t\t\t\t<select size=\"25\">\n";
		}
		foreach my $m ( sort @{$lynis_report_data{'loaded_kernel_module[]'}} ) { print OUT "\t\t\t\t\t\t\t<option>$m\n"; }
		print OUT "\t\t\t\t\t\t</select>\n";
	}
	$lynis_report_data{'journal_oldest_bootdate'} = "&nbsp;" if ((!defined($lynis_report_data{'journal_oldest_bootdate'})) or ($lynis_report_data{'journal_oldest_bootdate'} eq ""));
	$lynis_report_data{'journal_contains_errors'} = 0 if ((!defined($lynis_report_data{'journal_contains_errors'})) or ($lynis_report_data{'journal_contains_errors'} eq ""));
	print OUT <<END;
				</div>
			</div>
			<hr />
			<h3><a id="filesystem_info">filesystem/journalling info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
END
	print OUT "\t\t\t\t\t<td class=\"field_label\">oldest boot date:</td><td>$lynis_report_data{'journal_oldest_bootdate'}</td>\n";
	print OUT "\t\t\t\t\t<td class=\"field_label\">journal errors:</td><td>$to_bool{$lynis_report_data{'journal_contains_errors'}}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	print OUT "\t\t\t\t\t<td class=\"field_label\">journal disk size:</td><td>$lynis_report_data{'journal_disk_size'}</td>\n";
	print OUT "\t\t\t\t\t<td class=\"field_label\">last cordumps:</td><td>$lynis_report_data{'journal_coredumps_lastday'}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	if ((exists($lynis_report_data{'file_systems_ext[]'})) and (ref($lynis_report_data{'file_systems_ext[]'}) eq "ARRAY")) {
		print OUT "\t\t\t\t\t\t<td>filesystems:</td><td>".join("<br />\n", @{$lynis_report_data{'file_systems_ext[]'}})."</td>\n";
	} else {
		if (defined($lynis_report_data{'file_systems_ext[]'})) {
			print OUT "\t\t\t\t\t\t<td class=\"field_label\">filesystems:</td><td>$lynis_report_data{'file_systems_ext[]'}</td>\n";
		} else {
			print OUT "\t\t\t\t\t\t<td class=\"field_label\">filesystems:</td><td>&nbsp;</td>\n";
		}
	}
	if ((exists($lynis_report_data{'swap_partition[]'})) and (ref($lynis_report_data{'swap_partition[]'}) eq "ARRAY")) {
		#warn colored("swap_partition[] is an array".Dumper(\@{$lynis_report_data{'swap_partition[]'}}), "yellow") if ($verbose);
		warn colored("swap_partition[] is an array", "yellow") if ((($verbose) and ($verbose > 1 )) or ($debug));
		if (scalar(@{$lynis_report_data{'swap_partition[]'}}) == 1) {
			if ($lynis_report_data{'swap_partition[]'}[0] =~ /\,/) {
				my @p = split(/\,/, $lynis_report_data{'swap_partition[]'}[0]);
				$lynis_report_data{'swap_partition[]'} = \@p;
			}
		} else {
			#if (scalar(@{$lynis_report_data{'swap_partition[]'}}) > 1) {
			#	print color('bold magenta');
			#	print Dumper($lynis_report_data{'swap_partition[]'});
			#	print color('reset');
			#	@{$lynis_report_data{'swap_partition[]'}} = &dedup_array(@{$lynis_report_data{'swap_partition[]'}});
			#}
		}
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">swap partitions:</td><td>".join("<br />\n", @{$lynis_report_data{'swap_partition[]'}})."</td>\n";
	} else {
		if ((($verbose) and ($verbose > 1)) or ($debug)) {
			warn colored("swap_partition[] is a string.", "yellow") if ($verbose);
			print OUT "\t\t\t\t\t\t<td class=\"field_label\">swap partitions:</td><td>$lynis_report_data{'swap_partition[]'}</td>\n";
		}
	}
	$lynis_report_data{'journal_bootlogs'} = 0 if ((!defined($lynis_report_data{'journal_bootlogs'})) or ($lynis_report_data{'journal_bootlogs'} eq ""));
	print OUT <<END;
					</tr>
END
	if (ref($lynis_report_data{'lvm_volume_group[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">LVM volume group(s):</td><td>".join("<br />\n", @{$lynis_report_data{'lvm_volume_group[]'}})."</td>";
	} else {
		print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">LVM volume group(s):</td><td>$lynis_report_data{'lvm_volume_group[]'}</td>";
	}
	if (ref($lynis_report_data{'lvm_volume[]'}) eq 'ARRAY') {
		print OUT "<td class=\"field_label\">LVM volume(s)</td><td>".join("<br />\n", @{$lynis_report_data{'lvm_volume[]'}})."</td></tr>\n";
	} else {
		print OUT "<td class=\"field_label\">LVM volume(s)</td><td>$lynis_report_data{'lvm_volume[]'}</td></tr>\n";
	}
	print OUT <<END;
					<tr>
						<td class="field_label">journal boot log found:</td><td>$to_bool{$lynis_report_data{'journal_bootlogs'}}</td>
						<td class="field_label"></td><td></td>
					</tr>
				</table>
				<br />
				<h4>journal metadata:</h4><a id="journalMetaDataLink" href="javascript:toggle('journalMetaDataLink', 'journalMetaDataToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="journalMetaDataToggle" style="display:none">
END
	if ((exists($lynis_report_data{'journal_meta_data'})) and (ref($lynis_report_data{'journal_meta_data'}) eq "ARRAY")) {
		foreach my $md ( @{$lynis_report_data{'journal_meta_data'}} ) {
			print OUT "\t\t\t\t\t<table>\n";
			my @fields = split(/,/, $md);
			foreach my $f ( @fields ) {
				my ($key,$val);
				#print grep(/\:/, split(//, $f))."\n"; 
				if (grep(/\:/, split(//, $f)) > 1) {
					$key = substr($f,0,index($f,":"));
					$val = substr($f,(index($f,":")+1));
				} else {
					($key,$val) = split(/:/, $f);
				}
				#print "k: $key v: $val \n";
				next if (!defined($key));
				if ((!defined($val)) or ($val eq "")) { $val = "&nbsp;"; }
				
				print OUT "\t\t\t\t\t\t<tr><td>$key\:</td><td>$val</td></tr>\n";
			}
			print OUT "\t\t\t\t\t</table>\n<br />\n";
		}
	} else { 
		warn colored("Didn't find journal_meta_data object!", "yellow") if ((($verbose) and ($verbose > 1)) or ($debug)); 
	}

##########################################
### SERVICE INFO
##########################################
	print OUT <<END;
				</div>
			</div>
			<hr />
			<h3><a id="service_info">service info:</a></h3>
			<div class="content_subsection">
				<table>
END
	foreach my $prog ( sort qw( redis ntp_daemon mysql ssh_daemon dhcp_client arpwatch audit_daemon postgresql linux_auditd nginx ) ) {
		if ((defined($lynis_report_data{$prog.'_running'})) and ($lynis_report_data{$prog.'_running'} ne "")) {
			print OUT "\t\t\t\t\t<tr><td class=\"field_label\">$prog running:</td><td>$to_bool{$lynis_report_data{$prog.'_running'}}</td></tr>\n";
		} else {
			print OUT "\t\t\t\t\t<tr><td class=\"field_label\">$prog running:</td><td>$to_bool{0}</td></tr>\n";
		}
	}
	print OUT "\t\t\t\t</table>\n";
	print OUT "\t\t\t\t<h4>daemon info:</h4>\n";
	print OUT "\t\t\t\t\t<table>\n";
	print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">pop3 daemon:</td><td>$lynis_report_data{'pop3_daemon'}</td></tr>\n";
	print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">imap daemon:</td><td>$lynis_report_data{'imap_daemon'}</td></tr>\n";
	print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">smtp daemon:</td><td>$lynis_report_data{'smtp_daemon'}</td></tr>\n";
	print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">printing daemon:</td><td>$lynis_report_data{'printing_daemon'}</td></tr>\n";
	print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">ntp daemon:</td><td>$lynis_report_data{'ntp_daemon'}</td></tr>\n";
	if (ref($lynis_report_data{'scheduler[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">scheduler(s):</td><td>".join("<br />\n",@{$lynis_report_data{'scheduler[]'}})."</td></tr>\n";
	} else {
		print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">scheduler(s):</td><td>$lynis_report_data{'scheduler[]'}</td></tr>\n";
	}
	print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">service manager:</td><td>$lynis_report_data{'service_manager'}</td></tr>\n";
	print OUT "\t\t\t\t\t\t<tr><td class=\"field_label\">running service tool:</td><td>$lynis_report_data{'running_service_tool'}</td></tr>\n";
	print OUT "\t\t\t\t\t</table>\n";
	print OUT <<END;
				<h4>running services:</h4>
END
	if (scalar(@{$lynis_report_data{'running_service[]'}}) < 25) {
		print OUT "\t\t\t\t<select size=\"".scalar(@{$lynis_report_data{'running_service[]'}})."\">\n";
	} else {
		print OUT "\t\t\t\t<select size=\"25\">\n";
	}
	foreach my $svc ( @{$lynis_report_data{'running_service[]'}} ) { print OUT "\t\t\t\t\t<option>$svc\n"; }
	print OUT "\t\t\t\t</select>\n";
	print OUT <<END;
				<h5>ntp detail:</h5><a id="ntpDetailLink" href="javascript: toggle('ntpDetailLink','ntpDetailToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="ntpDetailToggle" style="display: none">
					<table>
						<tr>
							<td>ntp config found:</td><td>$to_bool{$lynis_report_data{'ntp_config_found'}}</td>
END
	if (ref($lynis_report_data{'ntp_config_file[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t\t<td>ntp config file:</td><td>".join("<br />\n", @{$lynis_report_data{'ntp_config_file[]'}})."</td>\n";
	} else {
		#warn colored("ntp config file object not an array! \n", "yellow");
		print OUT "\t\t\t\t\t\t\t<td>ntp config file:</td><td>$lynis_report_data{'ntp_config_file[]'}</td>\n";
	}
	print OUT <<END;
						</tr>
						<tr>
END
	print OUT "\t\t\t\t\t\t\t<td>ntp version:</td><td>$lynis_report_data{'ntp_version'}</td>\n";
	if (ref($lynis_report_data{'ntp_unreliable_peer[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t\t<td>unreliable peers:</td><td>".join("<br />\n", @{$lynis_report_data{'ntp_unreliable_peer[]'}})."</td>";
	} else {
		print OUT "\t\t\t\t\t\t\t<td>unreliable peers:</td><td>$lynis_report_data{'ntp_unreliable_peer[]'}</td>\n";
	}
	print OUT <<END;
						</tr>
						<tr><th colspan="4">NTP Config Type</th></tr>
						<tr>
END
	print OUT "\t\t\t\t\t\t\t<td>startup:</td><td>$to_bool{$lynis_report_data{'ntp_config_type_startup'}}</td>\n";
	print OUT "\t\t\t\t\t\t\t<td>daemon:</td><td>$to_bool{$lynis_report_data{'ntp_config_type_daemon'}}</td>\n";
	print OUT <<END;
						</tr>
						<tr>
END
	print OUT "\t\t\t\t\t\t\t<td>scheduled:</td><td>$to_bool{$lynis_report_data{'ntp_config_type_scheduled'}}</td>\n";
	print OUT "\t\t\t\t\t\t\t<td>event based:</td><td>$to_bool{$lynis_report_data{'ntp_config_type_eventbased'}}</td>\n";
	print OUT <<END;
						</tr>
					</table>
				</div><!-- END ntpDetailToggle div -->
				<br />
				<h5>nginx detail</h5>
				<table>
					<tr>
END
	print OUT "\t\t\t\t\t\t<td class=\"field_label\">main config file:</td><td>$lynis_report_data{'nginx_main_conf_file'}</td>\n";
	if (ref($lynis_report_data{'nginx_sub_conf_file[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t<td class=\"field_label\">other config file(s):</td><td>".join("<br />\n", @{$lynis_report_data{'nginx_sub_conf_file[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t<td class=\"field_label\">other config file(s):</td><td>$lynis_report_data{'nginx_sub_conf_file[]'}</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
END
	if (ref($lynis_report_data{'log_file'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">log file:</td><td>".join("<br />\n",@{$lynis_report_data{'log_file'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td class=\"field_label\">log file:</td><td>$lynis_report_data{'log_file'}</td>\n";
	}
	print OUT <<END;
						<td class="field_label"></td><td></td>
					</tr>
				</table>
END
	print OUT "\t\t\t\t<h5>nginx config options:</h5><a id=\"nginxConfigLink\" href=\"javascript: toggle('nginxConfigLink', 'nginxConfigToggle');\">&gt;&nbsp;show&nbsp;&lt;</a>\n";
	print OUT "\t\t\t\t\t<div id=\"nginxConfigToggle\" style=\"display:none;\">\n";
	print OUT "\t\t\t\t\t<ul>\n";
	if (ref($lynis_report_data{'nginx_config_option[]'}) eq 'ARRAY') {
		foreach my $o ( @{$lynis_report_data{'nginx_config_option[]'}} ) { print OUT "\t\t\t\t\t\t<li>$o</li>\n"; }
	} else {
		if ((defined($lynis_report_data{'nginx_config_option[]'})) and ($lynis_report_data{'nginx_config_option[]'} ne "")) {
			print OUT "\t\t\t\t\t\t<li>$lynis_report_data{'nginx_config_option[]'}</li>\n";
		} else {
			print OUT "\t\t\t\t\t\t<li>N/A - Unable to detect nginx config </li>\n";
			warn colored("nginx config options opbject not an array!", "yellow");
			print Dumper($lynis_report_data{'nginx_config_option[]'});
		}
	}
	print OUT "\t\t\t\t\t</ul>\n";
	print OUT <<END;
					</div><!-- END nginxConfigToggle div --><br />
					<h5>SSL/TLS protocols enabled:</h5>
					<a id="ssltlsProtoLink" href="javascript: toggle('ssltlsProtoLink', 'ssltlsProtoToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
					<div id="ssltlsProtoToggle" style="display:none;">
						<ul>
END
	if (ref($lynis_report_data{'ssl_tls_protocol_enabled[]'}) eq 'ARRAY') {
		foreach my $p ( @{$lynis_report_data{'ssl_tls_protocol_enabled[]'}} ) { print OUT "\t\t\t\t\t\t<li>$p</li>\n"; }
	} else {
		print OUT "\t\t\t\t\t\t<li>$lynis_report_data{'ssl_tls_protocol_enabled[]'}</li>\n";
		#warn colored("ssltls protocols object not an array! \n", "yellow");
		#print Dumper($lynis_report_data{'ssl_tls_protocol_enabled[]'});
	}
	print OUT "\t\t\t\t\t</ul>\n";
	print OUT "\t\t\t\t</div><!-- END ssltlsProtoToggle div --><br />\n";
	if (ref($lynis_report_data{'apache_version'}) eq 'ARRAY') {
		die colored("apache version is an array:\n".Dumper(\@{$lynis_report_data{'apache_version'}}), "bold red");
	}
	print OUT <<END;
					<h5>apache details:</h5>
					<a id="apacheDetailsLink" href="javascript:toggle('apacheDetailsLink','apacheDetailsToggle');">&gt; &nbsp; show &nbsp; &lt;</a>
					<div id="apacheDetailsToggle" style="display:none;">
						<table><tr><td>apache version:</td><td>$lynis_report_data{'apache_version'}</td></tr></table>
						<h5>apache modules found:</h5>
						<a id="apacheModulesLink" href="javascript:toggle('apacheModulesLink','apacheModulesToggle');">&gt; &nbsp; show &nbsp; &lt;</a>
						<div id="apacheModulesToggle" style="display:none;">
							<ul>
END
	if (ref($lynis_report_data{'apache_module[]'}) eq 'ARRAY') {
		foreach my $m ( sort @{$lynis_report_data{'apache_module[]'}} ) { print OUT "\t\t\t\t\t\t\t\t<li>$m</li>\n"; }
	} else {
		if ((($verbose) and ($verbose > 1)) or ($debug)) {
			warn colored("apache module object not an array!", "yellow");
			print Dumper($lynis_report_data{'apache_module[]'});
		}
	}
	print OUT "\t\t\t\t\t\t\t</ul>\n";
	print OUT "\t\t\t\t\t\t</div><!-- END apacheModulesToggle div -->\n";
	print OUT "\t\t\t\t\t</div><!-- END apacheDetailsToggle div -->\n";
	print OUT <<END;
				<h5>systemd detail:</h5><a id="systemdLink" href="javascript:toggle('systemdLink', 'systemdToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="systemdToggle" style="display:none;">
					<table>
						<tr>
END
	print OUT "\t\t\t\t\t\t<td>systemd version:</td><td>$lynis_report_data{'systemd_version'}</td>\n";
	print OUT "\t\t\t\t\t\t<td>systemd status:</td><td>$lynis_report_data{'systemd_status'}</td>\n";
	print OUT <<END;
						</tr>
						<tr>
END
	print OUT "\t\t\t\t\t\t<td>systemd builtin components:</td><td colspan=\"3\">$lynis_report_data{'systemd_builtin_components'}</td>\n";
	print OUT <<END;
						</tr>
					</table>
END
	print OUT <<END;
					<h5>systemd unit files:</h5><a id="systemdUnitFileLink" href="javascript:toggle('systemdUnitFileLink','systemdUnitFileToggle');">&gt; &nbsp; show &nbsp; &lt;</a>
					<div id="systemdUnitFileToggle" style="display:none;">
						<table>
							<tr><th>unit file</th><th>status</th><th></th><tr>
END
	if (ref($lynis_report_data{'systemd_unit_file[]'}) eq 'ARRAY') {
		foreach my $f ( sort @{$lynis_report_data{'systemd_unit_file[]'}} ) { 
			my ($f,$s,$t) = split(/\|/, $f);
			print OUT "\t\t\t\t\t\t\t<tr><td>$f</td><td>$s</td><td>$t</td></tr>\n"; 
		}
	} else {
		warn colored("systemd unit file object not an array! ", "yellow") if ((($verbose) and ($verbose > 1)) or ($debug));
	}
	print OUT <<END;
						</table>
					</div><!-- END systemdUnitFileToggle div -->
END
	print OUT <<END;
					<h5>systemd unit not found:</h5><a id="systemdUnitNotFoundLink" href="javascript:toggle('systemdUnitNotFoundLink','systemdUnitNotFoundToggle');">&gt; &nbsp; show &nbsp; &lt;</a>
					<div id="systemdUnitNotFoundToggle" style="display:none;">
						<ul>
END
	if (ref($lynis_report_data{'systemd_unit_not_found[]'})) {
		foreach my $unf ( sort @{$lynis_report_data{'systemd_unit_not_found[]'}} ) { print OUT "\t\t\t\t\t\t\t<li>$unf</li>\n"; }
	} else {
		warn colored("systemd unitnot found object not an array! ", "yellow") if ((($verbose) and ($verbose > 1)) or ($debug));
	}
	print OUT <<END; 
						</ul>
					</div><!-- END systemdUnitNotFoundToggle div -->
END
	print OUT <<END;
					<h5>systemd service not found:</h5><a id="systemdServiceNotFoundLink" href="javascript:toggle('systemdServiceNotFoundLink','systemdServiceNotFoundToggle');">&gt; &nbsp; show &nbsp; &lt;</a>
					<div id="systemdServiceNotFoundToggle" style="display:none;">
						<ul>
END
	if (ref($lynis_report_data{'systemd_service_not_found[]'}) eq 'ARRAY') {
		foreach my $snf ( sort @{$lynis_report_data{'systemd_service_not_found[]'}} ) { print OUT "\t\t\t\t\t\t\t<li>$snf</li>\n"; }
	} else {
		warn colored("systemd service not found object not an array! ", "yellow") if ((($verbose) and ($verbose > 1)) or ($debug));
	}
	print OUT <<END;
						</ul>
					</div><!-- END systemdServiceNotFoundToggle div -->
				</div><!-- END systemdToggle -->	
			</div><!-- END subcontent div -->
			<hr />
			<h3><a id="installed_packages">Installed packages:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td class="field_label">Number of packages installed:</td><td>$lynis_report_data{'installed_packages'}</td>
						<td class="field_label">Number of binaries found:</td><td>$lynis_report_data{'binaries_count'}</td>
					</tr>
				</table>
				<br />
				<a id="pkgLink" href="javascript: toggle('pkgLink', 'pkgContent');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="pkgContent" style="display: none">
END
	if (ref($lynis_report_data{'installed_packages_array'}) eq 'ARRAY') {
		if (scalar(@{$lynis_report_data{'installed_packages_array'}}) < 25) {
			print OUT "\t\t\t\t\t<select size=\"".scalar(@{$lynis_report_data{'installed_packages_array'}})."\">\n";
		} else {
			print OUT "\t\t\t\t\t<select size=\"25\">\n";
		}
		foreach my $p ( sort @{$lynis_report_data{'installed_packages_array'}} ) { chomp($p); print OUT "\t\t\t\t\t\t<option>$p\n"; }
		print OUT "\t\t\t\t\t</select>\n";
	}
	print OUT <<END;
				</div>	<!-- #jsToggle -->
			</div>	<!-- #subcontainer -->
			<div id="footer">
				<hr />
				<p><a href="http://jigsaw.w3.org/css-validator/check/referer">
					<img style="border:0;width:88px;height:31px;"
						src="http://jigsaw.w3.org/css-validator/images/vcss"
						alt="Valid CSS!" />
				</a></p>
			</div>	<!-- #footer -->
		</div>	<!-- #container -->
	</body>
</html>

END

	close OUT or die colored("There was a problem closing the output file ($output): $! ", "bold red");

	my @indexes = qw( lynis_version lynis_tests_done lynis_update_available license_key report_datetime_start report_datetime_end plugins_directory plugins_enabled finish report_version_major report_version_minor hostid hostid2 plugin_enabled_phase1[] hardening_index warning[] hostname domainname linux_kernel_version linux_config_file memory_size nameserver[] network_interface[] framework_grsecurity vm vmtype uptime_in_seconds linux_kernel_release os framework_selinux uptime_in_days os_fullname default_gateway[] cpu_nx cpu_pae linux_version os_version network_ipv6_address[] boot_loader suggestion[] manual manual[] linux_version cpu_pae cpu_nx network_ipv4_address[] network_mac_address[] os_name os_kernel_version os_kernel_version_full firewall_installed max_password_retry password_max_days password_min_days pam_cracklib password_strength_tested minimum_password_length package_audit_tool package_audit_tool_found );
	my @idx2 = qw( vulnerable_packages_found firewall_active firewall_software[] firewall_software auth_failed_logins_logged authentication_two_factor_enabled memory_units default_gateway authentication_two_factor_required malware_scanner_installed file_integrity_tool_installed file_integrity_tool_installed pam_module[] ids_ips_tooling[] ipv6_mode ipv6_only name_cache_used ldap_pam_enabled ntp_daemon_running mysql_running ssh_daemon_running dhcp_client_running arpwatch_running running_service[] audit_daemon_running installed_packages binaries_count installed_packages_array crond_running network_listen_port[] firewall_empty_ruleset automation_tool_present automation_tool_running[] file_integrity_tool ldap_auth_enabled password_max_l_credit password_max_u_credit password_max_digital_credit password_max_other_credit loaded_kernel_module[] plugin_directory package_manager[] linux_kernel_io_scheduler[] linux_kernel_type );
	my @idx3 = qw( details[] available_shell[] locate_db smtp_daemon smtp_daemon[] pop3_daemon ntp_daemon imap_daemon printing_daemon boot_service[] boot_uefi_boot_secure linux_default_runlevel boot_service_tool boot_uefi_booted systemctl_exit_code min_password_class session_timeout_enabled compiler_installed real_user[] home_directory[] swap_partition[] filesystem_ext[] journal_disk_size journal_coredumps_lastday journal_oldest_bootdate journal_contains_errors swap_partition[] file_systems_ext[] test_category test_group scheduler[] journal_meta_data boot_uefi_booted_secure service_manager running_service_tool binary_paths valid_certificate[] cronjob[] log_directory[] open_logfile[] journal_bootlogs log_rotation_tool log_rotation_config_found auditor deleted_file[] vulnerable_package[] malware_scanner[] file_integrity_tool[] plugin_firewall_iptables_list linux_amount_of_kernels ntp_config_type_startup ntp_config_type_scheduled compiler_world_executable[]);
	my @idx4 = qw( ntp_config_type_eventbased ntp_config_type_daemon ntp_config_file[] ntp_config_found ntp_version ntp_unreliable_peer[] postgresql_running linux_auditd_running linux_kernel_io_scheduler nginx_main_conf_file log_file nginx_sub_conf_file[] nginx_config_option[] ssl_tls_protocol_enabled[] systemd systemd_builtin_components systemd_version systemd_status plugin_processes_allprocesses usb_authorized_default_device[] systemd_unit_file[] systemd_unit_not_found[] systemd_service_not_found[] resolv_conf_search_domain[] expired_certificate[] compiler[] fail2ban_config fail2ban_enabled_service[] apache_version apache_module[] resolv_conf_domain redis_running nginx_running open_empty_log_file[] notebook lvm_volume_group[] lvm_volume[] container exception_event[] certificates certificate[] localhost-mapped-to manual_event[] syslog_daemon[] syslog_daemon_present apparmor_enabled apparmor_policy_loaded pam_pwquality selinux_status selinux_mode );
	my @idx5 = qw( auth_group_ids_unique auth_group_names_unique );
	push @indexes, @idx2, @idx3, @idx4, @idx5;
	foreach my $idx ( sort @indexes ) {
		delete($lynis_report_data{$idx});
	}

	if ($pdf) {
		require HTML::HTMLDoc;
		my $htmlobj = new HTML::HTMLDoc();
		$htmlobj->set_input_file($htmldoc);
		my $pdfdoc = $htmlobj->generate_pdf();
		$pdfdoc->to_file($output);
		my $errs = system("rm -f $htmldoc");
		if ($verbose) { print "Clean up return code: $errs \n"; }
	}	
}

if ($verbose) {
	print colored("I don't know how to handle these objects yet:\n", "yellow");
	print colored(Dumper(\%lynis_report_data), "yellow");
}

###############################################################################
# subs
###############################################################################
sub usage {

	if ((!$output) and (!$showversion)) {
		unless ($help) {
			print colored("You must specify an output file.\n", "yellow");
		}
	}

	print <<END;

$0 -h|--help -v|--verbose -E|--excel -j|--json -x|--xml -p|--pdf -o|--output

Where:

-h|--help			Display this useful message, then exit.
-v|--verbose			Display more detailed output.  This is typically used for debugging, but may provide insight when running into problems.
-i|--input			Input log filename.  Defaults to /var/log/lynis-report.dat.
-E|--excel			Output the report in Microsoft Excel binary format.
-j|--json			Output the data in JSON format.  It is recommended to pipe to /usr/bin/json_pp for easier (human) reading.  Output file name is optional for JSON output.
-x|--xml			Output the report as XML.
-p|--pdf			Output the report as a PDF.  This is simply a copy of the HTML report converted to PDF.  Could use refinement.
-o|--output			Specifies the output file to print the report to.

END
	exit 0;
}

# show script version and gather some relevant data for troubleshooting
sub show_version {
	my $uname_a = `uname -a`;
	chomp($uname_a);
	my $perl_v = `perl --version`;
	chomp($perl_v);
	print <<EOS;

SCRIPT VERSION:		$VERSION
UNAME: 			$uname_a
OS FullName: 		$lynis_report_data{'os_fullname'}
OS Version:		$lynis_report_data{'os_version'}
Perl Version:	
$perl_v

EOS
	exit 0;
}

# determine if a number is prime
sub is_prime {
	my $num = shift(@_);
	my $sqrt = sqrt($num);
	my $d = 2;
	while (1) {
		return 0 if ( $num % $d == 0 );
		return 1 if ( $d >= $sqrt );
		$d++;
	}
}

# deduplicate elements in an array
sub dedup_array {
	my $aryref = shift;
	my %hash;

	foreach my $ele ( @{$aryref} ) { $hash{$ele}++; }
	return sort keys(%hash);
}

# calculate the binary "score" for password complexity based off the lynis script findings
sub calc_password_complexity_score {
	my ($lc,$uc,$n,$o);
	if ($lynis_report_data{'password_max_l_credit'}) { $lc = 0b0001; } else { $lc = 0b0000; }
	if ($lynis_report_data{'password_max_u_credit'}) { $uc = 0b0010; } else { $uc = 0b0000; }
	if ($lynis_report_data{'password_max_digital_credit'}) { $n = 0b0100; } else { $n = 0b0000; }
	if ($lynis_report_data{'password_max_other_credit'}) { $o = 0b1000; } else { $o = 0b0000; }
	#printf "%#b\n%#b\n%#b\n%#b\n", $lc, $uc, $n, $o;
	my $score = ($lc + $uc + $n + $o);
	#printf "%#b\n", $score;
	return $score;
}

# give inconsistent keys a value
# some keys may be inconsistent because of OS/Distro version differences
# some keys mey be inconsistent because of the use of plugins
sub pop_inconsistent_keys {
	my $fmt = shift;
	my $lrd_hash_ref = shift;
	my @inconsistent_keys = qw( plugin_firewall_iptables_list notebook container valid_certificate[] usb_authorized_default_device[] expired_certificate[] certificates certificate[] syslog_daemon[] localhost-mapped-to resolv_conf_search_domain[] pam_pwquality malware_scanner[] compiler[] ids_ips_tooling[] fail2ban_config fail2ban_enabled_service[] pam_module[] linux_kernel_io_scheduler[] loaded_kernel_module[] journal_disk_size journal_coredumps_lastday lvm_volume_group[] running_service[] ntp_config_file[] ntp_version ntp_unreliable_peer[] nginx_main_conf_file nginx_sub_conf_file[] log_file nginx_config_option[] ssl_tls_protocol_enabled[] apache_version apache_module[] systemd_version systemd_status systemd_builtin_components systemd_unit_file[] systemd_unit_not_found[] systemd_service_not_found[] installed_packages_array pam_auth_brute_force_protection_module[] vulnerable_package[] plugin_enabled_phase1[] plugin_processes_allprocesses nameserver[] boot_service[] swap_partition[] lvm_volume[] file_systems_ext[] journal_meta_data deleted_file[] license_key pop3_daemon imap_daemon printing_daemon ntp_daemon scheduler[] service_manager running_service_tool cronjob[] apparmor_enabled apparmor_policy_loaded domainname selinux_status selinux_mode );

	foreach my $key ( sort @inconsistent_keys ) { 
		if ($key =~ /(?:notebook|container|apparmor_enabled|apparmor_policy_loaded|selinux_status)/) {		
			# boolean values
			$lrd_hash_ref->{$key} = 0;
		} elsif ($key =~ /(?:warning\[\]|running_service\[\])/) {
			# these keys expect to be arrays
			@{$lrd_hash_ref->{$key}} = qw( "NA" );
		} elsif ($key =~ /\bcertificates\b/) {
			# these keys expect to be an integer
			$lrd_hash_ref->{$key} = 0;
		} else {
			given ($fmt) {
				when (/excel/) { $lrd_hash_ref->{$key} = "NA"; }
				when (/json/) { $lrd_hash_ref->{$key} = "NA"; }
				default { $lrd_hash_ref->{$key} = "\&nbsp;"; }		# covers XML, PDF and HTML (default)
			}
		}
	}
	# should operate on the main \%lynis_report_data hash, so we shouldn't need to return anything.  Maybe success/fail?	
}		

# flatten an array
# dedupe it and remove arbitrary elements if legitimate ones exist.
sub flatten {
	my @ary = shift;
	# check if there's more than one element
	if (scalar(@ary) > 1) {
	# if so, dedup
		@ary = &dedup_array(@ary);
	# check again
		if (scalar(@ary) > 1) {
	# if > 1 check for "NA" or "&nbsp;"
	# remove if present
			for (my $i = 0; $i<=scalar(@ary); $i++) {
				delete $ary[$i] if ($ary[$i] =~ /(?:NA|\&nbsp;)/);
			}
	# else throw an error, or just return the array (?)
			if (scalar(@ary) > 1) { return @ary; }
	# if only one, return the scalar.
			elsif (scalar(@ary) == 1) { return $ary[0]; }
			else { die colored("flatten() array results in 0 elements.", "bold red"); }
		} elsif (scalar(@ary) == 1) { return $ary[0]; }
		else { die colored("flatten() array results in 0 elements.", "bold red"); }	
	} elsif (scalar(@ary) == 1) { return $ary[0]; } 
	else { die colored("flatten() array results in 0 elements.", "bold red"); }	
}
