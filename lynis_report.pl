#!/usr/bin/perl -w

use strict;
use warnings;
use feature qw( switch );
no if $] ge '5.018', warnings => "experimental::smartmatch";
use Term::ANSIColor;
use Getopt::Long qw( :config no_ignore_case bundling );
use Data::Dumper;
#use Spreadsheet::WriteExcel;
use Excel::Writer::XLSX;
#use File::Basename;
use HTML::HTMLDoc;

my ($help,$verbose,$excel,$output,$pdf);
GetOptions(
	'h|help'		=>	\$help,
	'v|verbose+'	=>	\$verbose,
	'E|excel'		=>	\$excel,
	'o|output=s'	=>	\$output,
	'p|pdf'			=>	\$pdf,
);

if ($help) { &usage; }

my %to_bool = (	0 => 'false', 1 => 'true' );
my %vm_mode = ( 0 => 'false', 1 => 'guest', 2 => 'host' );
my %to_long_severity = ( 'C' => 'Critical', 'S' => 'Severe', 'H' => 'High', 'M' => 'Medium', 'L' => 'Low', 'I' => 'Informational' );
my %systemd_uf_status_color = (
	'enabled'	=>	'#00ff00',
	'disabled'	=>	'#ff0000',
	'static'	=>	'inherit',
	'masked'	=>	'goldenrod'
);

my ($basename, $path, $suffix, $htmldoc);

if ($excel) {
	$output = 'report.xlsx' unless ((defined($output)) and ($output ne ""));
} elsif ($pdf) {
	$output = 'report.pdf' unless ((defined($output)) and ($output ne ''));
	$htmldoc = "$$.html";
} else {
	$output = "report.html" unless ((defined($output)) and ($output ne ""));
	$htmldoc = $output
}

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
if ($excel) { print "Excel "; }
elsif ($pdf) { print "PDF "; }
else { print "HTML "; }
print "format. \n";

# the report is easy to process, and actually doesn't contain the "audit findings"....just the data.
# but it is not our job to draw conclusions here, just present the findings of the tool.
open RPT, "<$lynis_report" or die colored("There was a problem opening the lynis report: $! \n", "bold red");
while (my $line = <RPT>) {
	next if ($line =~ /^#/);								# skip commented lines
	next if ($line =~ /Result.*allow\_url\_fopen.*/);		# This looks like a bug in the report output.  Skip it.
	chomp($line);
	my ($k, $v) = split(/=/, $line);
	if ((!defined($k)) or ($k eq "")) { next; }				# something went wonky -- we didn't get a valid key. so skip
	if ((!defined($v)) or ($v eq "")) { $v = "&nbsp;"; }	# fill with a blank(ish) value if nothing
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

@{$lynis_report_data{'automation_tool_running[]'}} = &dedup_array($lynis_report_data{'automation_tool_running[]'}) if (ref($lynis_report_data{'automation_tool_running[]'}) eq 'ARRAY');
@{$lynis_report_data{'boot_service[]'}} = &dedup_array($lynis_report_data{'boot_service[]'}) if (ref($lynis_report_data{'boot_service[]'}) eq "ARRAY");
@{$lynis_report_data{'cronjob[]'}} = &dedup_array($lynis_report_data{'cronjob[]'}) if (ref($lynis_report_data{'cronjob[]'}) eq 'ARRAY');

my $pass_score = &calc_password_complexity_score;

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
	print "$key, ".ref($lynis_report_data{$key})." \n" if (($verbose) and ($verbose > 1));
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

if ($excel) {
	# do the Excel thing....
	my $wb = Excel::Writer::XLSX->new($output);
	my $title_format = $wb->add_format();
	$title_format->set_size('32');

	my $subtitle_format = $wb->add_format();
	$subtitle_format->set_size('24');

	my $subsub_format = $wb->add_format();
	$subsub_format->set_size('16');

	my $summary_ws = $wb->add_worksheet('Summary');
	$summary_ws->write('B2', "lynis Asset Report", $title_format);
	$summary_ws->write('B3', "created by "); 
	$summary_ws->write_url('C3', "http://github.com/d4t4king/lynis_report.git", '', 'lynis_report');
	$summary_ws->write('A4', "Host Findings:", $subtitle_format);
	$summary_ws->write('A5', "hardening index:");
	$summary_ws->write('B5', $lynis_report_data{'hardening_index'});
	$summary_ws->write('A7', "warnings \(".scalar(@{$lynis_report_data{'warning[]'}})."\):", $subsub_format);
	my @table_data;
	my $header_row = [ 'Warning ID', 'Description', 'Severity', 'F4' ];
	if (exists($lynis_report_data{'warning[]'})) {
		if (ref($lynis_report_data{'warning[]'}) eq 'ARRAY') {
			if ($lynis_report_data{'warning[]'}[0] =~ /\|/) {
				foreach my $warn ( sort @{$lynis_report_data{'warning[]'}} ) {
					my ($warn_id,$warn_desc,$warn_sev,$warn_f4) = split(/\|/, $warn);
					push @table_data, [$warn_id,$warn_desc,$warn_sev,$warn_f4];
				}
			}
		}
	}
	my %params = (
		'data'			=>	\@table_data,
		'header_row'	=>	$header_row,
	);
	my $last_row_number = 8 + scalar(@table_data);
	$summary_ws->add_table("A8:D$last_row_number", \%params);

} else {
	open OUT, ">$htmldoc" or die colored("There was a problem opening the output file ($htmldoc): $! \n", "bold red");
	print OUT <<END;
<!DOCTYPE HTML>
<html lang="en">
	<head>
		<title>lynis report</title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<style type="text/css">
			html,body {color: #fff; background-color: #000;}
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
				my $warn_id = ${$lynis_report_data{'warning[]'}}[0];
				my $warn_desc = ${$lynis_report_data{'warning[]'}}[1];
				my $warn_sev = ${$lynis_report_data{'warning[]'}}[2];
				my $warn_f4 = ${$lynis_report_data{'warning[]'}}[3];
				print OUT "\t\t\t\t\t<tr><td>$warn_id</td><td>$warn_desc</td><td>$to_long_severity{$warn_sev}</td><td>$warn_f4</td></tr>\n";
			} else {
				die colored("Unexpected ARRAY format! \n", "bold red");
			}
		} else {
			die colored("warning[] not ARRAY ref!: ".ref($lynis_report_data{'warning[]'})."\n", "bold red");
		}
	}
	print OUT <<END;
				</table>
			</div>
END
	print OUT "\t\t\t<h4>suggestions (".scalar(@{$lynis_report_data{'suggestion[]'}})."):</h4>\n";
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
			print OUT "\t\t\t\t<select size=\"10\" name=\"lbDeletedFiles\">\n";
			foreach my $f ( @{$lynis_report_data{'deleted_file[]'}} ) { print OUT "\t\t\t\t\t<option>$f\n"; }
		} else {
			warn colored("Deleted files object not an array! \n", "yellow");
			print Dumper($lynis_report_data{'delete_file[]'});
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
			warn colored("Vulnerable package pbject not an array! \n", "yellow");
			print Dumper($lynis_report_data{'vulnerable_package[]'});
		}
	}
	# It's easier to move stuff around if there is one cell (or cell group) per libe for the tables.  Maybe this
	# isn't ideal HTML writing, but it makes sense when writing the tool.
	$lynis_report_data{'lynis_update_available'} = 0 if ((!defined($lynis_report_data{'lynis_update_available'})) or ($lynis_report_data{'lynis_update_available'} eq ""));
	print OUT <<END;
			</div>
			<hr />
			<h3><a id="lynis_info">lynis info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td>lynis version:</td><td>$lynis_report_data{'lynis_version'}</td>
						<td>lynis tests done:</td><td>$lynis_report_data{'lynis_tests_done'}</td>
					</tr>
					<tr>
						<td>lynis update available:</td><td>$to_bool{$lynis_report_data{'lynis_update_available'}}</td>
END
	if ((defined($lynis_report_data{'license_key'})) and ($lynis_report_data{'license_key'} ne "")) {
		print OUT "\n\n\n\n\n\n<td>license key:</td><td>$lynis_report_data{'license_key'}</td>\n";
	} else {
		print OUT "\n\n\n\n\n\n<td>license key:</td><td>&nbsp;</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
						<td colspan="2">report version:</td><td colspan="2">$lynis_report_data{'report_version_major'}.$lynis_report_data{'report_version_minor'}</td>
					</tr>
					<tr>
						<td>test category:</td><td>$lynis_report_data{'test_category'}</td>
						<td>test group:</td><td>$lynis_report_data{'test_group'}</td>
					</tr>
					<tr>
						<td>number of plugins enabled:</td><td>$lynis_report_data{'plugins_enabled'}</td>
						<td>plugin directory:</td><td>$lynis_report_data{'plugin_directory'}</td>
					</tr>
					<tr>
END

	print OUT "\t\t\t\t\t\t<td>phase 1 plugins enabled:</td><td colspan=\"3\">\n";
	print OUT "\t\t\t\t\t\t\t<table id=\"lynis_plugins_table\">\n";
	foreach my $plug ( sort @{$lynis_report_data{'plugin_enabled_phase1[]'}} ) { 
		my ($n,$v) = split(/\|/, $plug);
		print OUT "\t\t\t\t\t\t\t\t<tr><td>name:</td><td>$n</td><td>version:</td><td>$v</td></tr>\n";
	}
	print OUT "\t\t\t\t\t\t\t</table>\n";
	print OUT "\t\t\t\t\t\t</td>\n";
	print OUT <<END;
					</tr>
					<tr>
						<td>report start time:</td><td>$lynis_report_data{'report_datetime_start'}</td><td>report end time:</td><td>$lynis_report_data{'report_datetime_end'}</td>
					</tr>
					<tr><td>hostid:</td><td colspan="3">$lynis_report_data{'hostid'}</td></tr>
					<tr><td>hostid:</td><td colspan="3">$lynis_report_data{'hostid2'}</td></tr>
END
	print OUT "\t\t\t\t\t<tr><td>Plugin-firewall iptables list:</td><td colspan=\"3\">".join("<br />\n", @{$lynis_report_data{'plugin_firewall_iptables_list'}})."</td></tr>\n";
	print OUT "\t\t\t\t</table>\n";
	if ((exists($lynis_report_data{'plugin_processes_allprocesses'})) and ($lynis_report_data{'plugin_processes_allprocesses'} ne "")) {
		print OUT "\t\t\t\t<h5>Plugin-processes: discovered processes:</h5>\n";
		if (ref($lynis_report_data{'plugin_processes_allprocesses'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t<select size=\"10\" name=\"lbPluginProcessesAllProcesses\" >\n";
			foreach my $p ( sort @{$lynis_report_data{'plugin_processes_allprocesses'}} ) { print OUT "\t\t\t\t\t\t<option>$p\n"; }
			print OUT "\t\t\t\t\t</select>\n";
		} else {
			warn colored("plugin processess allprocesses object not an array! \n", "yellow");
			print Dumper($lynis_report_data{'plugin_processes_allprocesses'});
		}
	}
	print OUT <<END;
			</div>
			<hr />
			<h3><a id="host_info">host info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td>hostname:</td><td>$lynis_report_data{'hostname'}</td>
						<td>domainname:</td><td>$lynis_report_data{'domainname'}</td>
END
	if ((defined($lynis_report_data{'resolv_conf_domain'})) and ($lynis_report_data{'resolv_conf_domain'} ne "")) {
		print OUT "\t\t\t\t\t\t<td>resolv.conf domain:</td><td>$lynis_report_data{'resolv_conf_domain'}</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td>resolv.conf domain:</td><td>&nbsp;</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
						<td>os:</td><td>$lynis_report_data{'os'}</td>
						<td>os fullname:</td><td>$lynis_report_data{'os_fullname'}</td>
						<td>os_version:</td><td>$lynis_report_data{'os_version'}</td>
					</tr>
					<tr>
						<td>GRSecurity:</td><td>$to_bool{$lynis_report_data{'framework_grsecurity'}}</td>
						<td>SELinux:</td><td>$to_bool{$lynis_report_data{'framework_selinux'}}</td>
						<td>memory:</td><td>$lynis_report_data{'memory_size'} $lynis_report_data{'memory_units'}</td>
					</tr>
					<tr>
						<td>linux version:</td><td>$lynis_report_data{'linux_version'}</td>
						<td>pae enabled:</td><td>$to_bool{$lynis_report_data{'cpu_pae'}}</td>
						<td>nx enabled:</td><td>$to_bool{$lynis_report_data{'cpu_nx'}}</td>
					</tr>
					<tr>
END
	print OUT "\t\t\t\t\t\t<td>Available shells:</td><td>".join("<br />\n", @{$lynis_report_data{'available_shell[]'}})."</td>\n";
	$lynis_report_data{'locate_db'} = "&nbsp;" if ((!defined($lynis_report_data{'locate_db'})) or ($lynis_report_data{'locate_db'} eq ""));
	#print STDERR colored($lynis_report_data{'vm'}."\n", "bold magenta");
	$lynis_report_data{'vm'} = 0 if ((!defined($lynis_report_data{'vm'})) or ($lynis_report_data{'vm'} eq ""));
	#print STDERR colored($lynis_report_data{'vm'}."\n", "bold magenta");
	print OUT "\t\t\t\t\t<td>locate db:</td><td>$lynis_report_data{'locate_db'}</td>\n";
	print OUT "\t\t\t\t\t<td>uptime (days):</td><td>$lynis_report_data{'uptime_in_days'}</td>\n";
	print OUT <<END;
					</tr>
					<tr>
						<td>vm:</td><td>$vm_mode{$lynis_report_data{'vm'}}</td>
END
	if ((defined($lynis_report_data{'vmtype'})) and ($lynis_report_data{'vmtype'} ne "")) {
		print OUT "\t\t\t\t\t\t<td>vm_type:</td><td>$lynis_report_data{'vmtype'}</td>\n";
	} else{
		print OUT "\t\t\t\t\t\t<td>vm_type:</td><td>&nbsp;</td>\n";
	}
	print OUT <<END;
						<td>uptime (secs):</td><td>$lynis_report_data{'uptime_in_seconds'}</td>
					</tr>
					<tr>
						<td>binary paths:</td><td colspan="2">$lynis_report_data{'binary_paths'}</td>
END
	print OUT "\t\t\t\t\t\t<td>certificates:</td><td colspan=\"2\">".join("<br />\n",@{$lynis_report_data{'valid_certificate[]'}})."</td>\n";
	print OUT <<END;
					</tr>
					<tr>
END
	if (exists($lynis_report_data{'usb_authorized_default_device[]'})) {
		print OUT "\t\t\t\t\t\t<td>authorized default USB devices:</td><td colspan=\"2\">".join("<br \>\n", @{$lynis_report_data{'usb_authorized_default_device[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td>authorized default USB devices:</td><td colspan=\"2\">&nbsp;</td>\n";
	}
	if (exists($lynis_report_data{'expired_certificate[]'})) {
		print OUT "\t\t\t\t\t\t<td>expired certificates:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'expired_certificate[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td>expired certificates:</td><td colspan=\"2\">&nbsp;</td>\n";
	}
	print OUT <<END;
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
						<td>log rotation tool:</td><td>$lynis_report_data{'log_rotation_tool'}</td>
						<td>log rotation config found:</td><td>$to_bool{$lynis_report_data{'log_rotation_config_found'}}</td>
					</tr>
				</table>
				<br />
				<h4>log directories:</h4>
END
	if (ref($lynis_report_data{'log_directory[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t<select size=\"10\" name=\"lbLogDirectories\">\n";
		foreach my $ld ( @{$lynis_report_data{'log_directory[]'}} ) { print OUT "\t\t\t\t\t\t<option>$ld\n"; }
		print OUT "\t\t\t\t\t</select>\n";
	}
	print OUT "\t\t\t\t\t<h4>open log files:</h4>\n";
	if (ref($lynis_report_data{'open_logfile[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t<select size=\"10\" name=\"blOpenLogFiles\">\n";
		foreach my $lf ( @{$lynis_report_data{'open_logfile[]'}} ) { print OUT "\t\t\t\t\t\t<option>$lf\n"; }
		print OUT "\t\t\t\t\t</select>\n";
	}
	print OUT <<END;
			</div>
			<hr />
			<h3><a id="network_info">network info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td>IPv6 Mode:</td><td>$lynis_report_data{'ipv6_mode'}</td>
						<td>IPv6 Only:</td><td>$to_bool{$lynis_report_data{'ipv6_only'}}</td>
					</tr>
END
	print OUT "\t\t\t\t\t<tr><td colspan=\"2\">network interfaces:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'network_interface[]'}})."</td></tr>\n";
	print OUT "\t\t\t\t\t<tr><td colspan=\"2\">ipv4 addresses:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'network_ipv4_address[]'}})."</td></tr>\n";
	print OUT "\t\t\t\t\t<tr><td colspan=\"2\">ipv6 addresses:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'network_ipv6_address[]'}})."</td></tr>\n";
	print OUT "\t\t\t\t\t<tr><td colspan=\"2\">Default Gateway</td><td colspan=\"2\">$lynis_report_data{'default_gateway[]'}</td></tr>\n";
	print OUT "\t\t\t\t\t<tr>\n";
	#print STDERR "Should be ARRAY: |".ref($lynis_report_data{'network_mac_address[]'})."|\n";
	if (ref($lynis_report_data{'network_mac_address[]'}) eq "ARRAY") {
		print OUT "\t\t\t\t\t\t<td>MAC Address:</td><td>".join("<br />\n", @{$lynis_report_data{'network_mac_address[]'}})."</td>\n";
	} elsif ((defined($lynis_report_data{'network_mac_address[]'})) and ($lynis_report_data{'network_mac_address[]'} ne "")) {
		print OUT "\t\t\t\t\t\t<td>MAC Address:</td><td>$lynis_report_data{'network_mac_address[]'}</td>\n";
	} else { 
		print OUT "\t\t\t\t\t\t<td>MAC Address:</td><td>&nbsp;</td>\n";
	}
	print OUT <<END;
						<td>Name Cache Used:</td><td>$to_bool{$lynis_report_data{'name_cache_used'}}</td>
					</tr>
					<tr>
						<td colspan="2">resolv.conf search domain:</td>
END
	if (exists($lynis_report_data{'resolv_conf_search_domain[]'})) {
		#print STDERR colored($lynis_report_data{'resolv_conf_search_domain[]'}."\n", "bold magenta");
		if (ref($lynis_report_data{'resolv_conf_search_domain[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t\t<td colspan=\"2\">".join("<br />\n",@{$lynis_report_data{'resolv_conf_search_domain[]'}})."</td>\n";
		#} elsif (ref($lynis_report_data{'resolv_conf_search_domain[]'}) eq 'HASH') {
		#	print OUT "\t\t\t\t\t\t<td colspan=\"2\">".join("<br />\n",keys(%{$lynis_report_data{'resolv_conf_search_domain[]'}}))."</td>\n";
		} else {
			print OUT "\t\t\t\t\t\t<td colspan=\"2\">$lynis_report_data{'resolv_conf_search_domain[]'}</td>\n";
		}
	}
	print OUT <<END;
					</tr>
				</table>
				<h4>Open Ports:</h4>
				<table>
					<tr><td>IP Address</td><td>Port</td><td>Protocol</td><td>Daemon/Process</td><td>???</td></tr>
END

	foreach my $obj ( sort @{$lynis_report_data{'network_listen_port[]'}} ) {
		my ($ipp,$proto,$daemon,$dunno) = split(/\|/, $obj);
		my ($ip,$port);
		if (grep(/\:/, split(//, $ipp)) > 1) {
			# must be an IPv6 address;
			$port = substr($ipp, 0, index($ipp,":"));
			$ip = substr($ipp,(index($ipp,":")+1));
		} else {
			# must be IPv4
			($ip,$port) = split(/\:/, $ipp);
		}
		print OUT "\t\t\t\t\t<tr><td>$ip</td><td>$port</td><td>$proto</td><td>$daemon</td><td>$dunno</td></tr>\n";
	}
	print OUT <<END;
				</table>
			</div>
			<hr />
			<h3><a id="security_info">security info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td>Host Firewall Installed:</td><td>$to_bool{$lynis_report_data{'firewall_installed'}}</td>
						<td>Firewall Software:</td><td>$lynis_report_data{'firewall_software'}</td>
						<td>Firewall Empty Ruleset:</td><td>$to_bool{$lynis_report_data{'firewall_empty_ruleset'}}</td>
						<td>Firewall Active:</td><td>$to_bool{$lynis_report_data{'firewall_active'}}</td>
					</tr>
					<tr>
						<td>Package Audit Tools Found:</td><td>$to_bool{$lynis_report_data{'package_audit_tool_found'}}</td>
						<td>Package Audit Tool:</td><td>$lynis_report_data{'package_audit_tool'}</td>
						<td>Vulnerable Packages Found:</td><td>$lynis_report_data{'vulnerable_packages_found'}</td>
						<td>Package Manager:</td><td>$lynis_report_data{'package_manager[]'}</td>
					</tr>
					<tr>
						<td>Two-Factor Authentication Enabled:</td><td>$to_bool{$lynis_report_data{'authentication_two_factor_enabled'}}</td>
						<td>Two-Factor Authentication Required:</td><td>$to_bool{$lynis_report_data{'authentication_two_factor_required'}}</td>
						<td>LDAP PAM Module Enabled:</td><td>$to_bool{$lynis_report_data{'ldap_pam_enabled'}}</td>
						<td>LDAP Auth Enabled:</td><td>$to_bool{$lynis_report_data{'ldap_auth_enabled'}}</td>
					</tr>
					<tr>
						<td>Minimum Password Length:</td><td>$lynis_report_data{'minimum_password_length'}</td>
						<td>Maximum Password Days:</td><td>$lynis_report_data{'password_max_days'}</td>
						<td>Minimum Password Days:</td><td>$lynis_report_data{'password_min_days'}</td>
						<td>Maximum Password Retries:</td><td>$lynis_report_data{'max_password_retry'}</td>
					</tr>
					<tr>
END
	printf OUT "\t\t\t\t\t\t<td>Password Complexity Score:</td><td>%#b</td>\n", $pass_score;
	print OUT <<END;
						<td>PAM Cracklib Found:</td><td>$to_bool{$lynis_report_data{'pam_cracklib'}}</td>
						<td>Password Strength Tested:</td><td>$to_bool{$lynis_report_data{'password_strength_tested'}}</td>
						<td>Failed Logins Logged:</td><td>$lynis_report_data{'auth_failed_logins_logged'}</td>
					</tr>
					<tr>
						<td>File Integrity Tool Installed:</td><td>$to_bool{$lynis_report_data{'file_integrity_tool_installed'}}</td>
						<td>File Integrity Tool:</td><td>$lynis_report_data{'file_integrity_tool'}</td>
						<td>Automation Tool Present:</td><td>$to_bool{$lynis_report_data{'automation_tool_present'}}</td>
END
	if (ref($lynis_report_data{'automation_tool_running[]'}) eq 'ARRAY') {
		print OUT "\t\t\t\t\t\t<td>Automation Tool:</td><td>".join("<br />\n", @{$lynis_report_data{'automation_tool_running[]'}})."</td>\n";
	} elsif ((defined($lynis_report_data{'automation_tool_running[]'})) and ($lynis_report_data{'automation_tool_running[]'} ne "")) {
		print OUT "\t\t\t\t\t\t<td>Automation Tool:</td><td>$lynis_report_data{'automation_tool_running[]'}</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td>Automation Tool:</td><td>&nbsp;</td>\n";
	}
	print OUT <<END;
					</tr>
					<tr>
						<td>Malware Scanner Installed:</td><td>$to_bool{$lynis_report_data{'malware_scanner_installed'}}</td>
END
	if (exists($lynis_report_data{'malware_scanner[]'})) {
		print OUT "\t\t\t\t\t\t<td>Malware Scanner(s):</td><td>".join("<br />\n", @{$lynis_report_data{'malware_scanner[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td>Malware Scanner(s):</td><td>&nbsp;</td>\n";
	}
		
	print OUT <<END;
						<td>compiler installed:</td><td>$to_bool{$lynis_report_data{'compiler_installed'}}</td>
END
	print OUT "\t\t\t\t\t\t<td>compilers:</td><td>".join("<br />\n", @{$lynis_report_data{'compiler[]'}})."</td>\n";
	print OUT <<END; 
					</tr>
					<tr>
END
	if (exists($lynis_report_data{'ids_ips_tooling[]'})) {
		print OUT "\t\t\t\t\t\t<td>IDS/IPS Tooling</td><td>$lynis_report_data{'ids_ips_tooling[]'}</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td>IDS/IPS Tooling</td><td>&nbsp;</td>\n";
	}
	if (exists($lynis_report_data{'fail2ban_config'})) {
		if (ref($lynis_report_data{'fail2ban_config'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t\t<td>fail2ban config file(s):</td><td>".join("<br />\n", @{$lynis_report_data{'fail2ban_config'}})."</td>\n";
		} else {
			print OUT "\t\t\t\t\t\t<td>fail2ban config file(s):</td><td>$lynis_report_data{'fail2ban_config'}</td>\n";
		}
	}
	if (exists($lynis_report_data{'fail2ban_enabled_service[]'})) {
		if (ref($lynis_report_data{'fail2ban_enabled_service[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t\t<td>fail2ban enabled service(s):</td><td>".join("<br />\n", @{$lynis_report_data{'fail2ban_enabled_service[]'}})."</td>\n";
		} else {
			print OUT "\t\t\t\t\t\t<td>fail2ban enabled service(s):</td><td>$lynis_report_data{'fail2ban_enabled_service[]'}</td>\n";
		}
	}
	print OUT <<END;
						<td></td><td></td>
					</tr>
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
					<table class="list">
END
	my $arrlen = scalar(@{$lynis_report_data{'pam_module[]'}});
	#print "ARRLEN: $arrlen \n";
MAKECOLUMNS1:
	if (($arrlen % 5) == 0) {
		#print "ARRLEN divisible by 5. \n";
		for (my $i=0;$i<$arrlen;$i+=5) {
			print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'pam_module[]'}}[$i]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 1)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 2)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 3)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 4)]</td></tr>\n";
		}
	} elsif (($arrlen % 4) == 0) {
		warn colored("ARRLEN divisible by 4. \n", "yellow");
		for (my $i=0;$i<$arrlen;$i+=4) {
			print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'pam_module[]'}}[$i]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 1)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 2)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 3)]</td></tr>\n";
		}
	} elsif (($arrlen % 3) == 0) {
		#print "ARRLEN divisible by 3. \n";
		for (my $i=0;$i<$arrlen;$i+=3) {
			print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'pam_module[]'}}[$i]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 1)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 2)]</td></tr>\n";
		}
	} elsif (($arrlen % 2) == 0) {
		#print "ARRLEN divisible by 2. \n";
		for (my $i=0;$i<$arrlen;$i+=2) {
			print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'pam_module[]'}}[$i]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 1)]</td></tr>\n";
		}
	} else {
		if (&is_prime($arrlen)) { 
			print colored("Number ($arrlen) is prime. \n", "bold yellow") if (($verbose) and ($verbose > 1)); 
			$arrlen++;
			goto MAKECOLUMNS1;
		}
		die colored("ARRLEN appears to be number with a divisor larger than 5 or 1 ($arrlen) \n", "bold red");
	}
if ((!defined($lynis_report_data{'boot_service_tool'})) or ($lynis_report_data{'boot_service_tool'} eq "")) { $lynis_report_data{'boot_service_tool'} = "&nbsp;"; }
	print OUT <<END;
					</table>
				</div>
			</div>
			<hr />
			<h3><a id="boot_info">boot info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td>UEFI booted:</td><td>$to_bool{$lynis_report_data{'boot_uefi_booted'}}</td>
						<td>UEFI booted secure:</td><td>$to_bool{$lynis_report_data{'boot_uefi_booted_secure'}}</td>
					</tr>
					<tr>
						<td>default runlevel:</td><td>$lynis_report_data{'linux_default_runlevel'}</td>
						<td>boot service tool:</td><td>$lynis_report_data{'boot_service_tool'}</td>
					</tr>
				</table>
END
	print OUT "\t\t\t\t<h4>services started at boot:</h4>\n";
	if (!defined($lynis_report_data{'boot_service[]'})) {
		print OUT "\t\t\t\t\t<ul><li>N/A - Unable to detect boot services.</li></ul>\n";
	} elsif (ref($lynis_report_data{'boot_service[]'}) eq "ARRAY") {
		print OUT "\t\t\t\t\t<ul>\n";
		foreach my $svc ( @{$lynis_report_data{'boot_service[]'}} ) {
			print OUT "\t\t\t\t\t\t<li>$svc</li>\n";
		}
		print OUT "\t\t\t\t\t</ul>\n";
	} else {
		warn colored("boot_service[] object not an array", "yellow");
		print Dumper($lynis_report_data{'boot_service[]'});
	}
	$lynis_report_data{'linux_kernel_io_scheduler'} = "&nbsp;" if ((!defined($lynis_report_data{'linux_kernel_io_scheduler'})) or ($lynis_report_data{'linux_kernel_io_scheduler'} eq ""));
	$lynis_report_data{'linux_amount_of_kernels'} = "&nbsp;" if ((!defined($lynis_report_data{'linux_amount_of_kernels'})) or ($lynis_report_data{'linux_amount_of_kernels'} eq ""));
	#print Dumper($lynis_report_data{'linux_kernel_io_scheduler'});
	print OUT <<END;
			</div>
			<hr />
			<h3><a id="kernel_info">kernel info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td>kernel version:</td><td>$lynis_report_data{'linux_kernel_version'}</td>
						<td>full kernel version:</td><td>$lynis_report_data{'os_kernel_version_full'}</td>
					</tr>
					<tr>
						<td>kernel release version:</td><td>$lynis_report_data{'linux_kernel_release'}</td>
						<td>kernel IO scheduler:</td><td>$lynis_report_data{'linux_kernel_io_scheduler[]'}</td>
					</tr>
					<tr>
						<td>linux kernel type:</td><td>$lynis_report_data{'linux_kernel_type'}</td>
						<td>number of kernels available:</td><td>$lynis_report_data{'linux_amount_of_kernels'}</td>
					</tr>
				</table>
				<h4>kernel modules loaded:</h4><a id="kernelModLink" href="javascript:toggle('kernelModLink', 'kernelModToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="kernelModToggle" style="display: none">
					<table class="list">
END
	$arrlen = scalar(@{$lynis_report_data{'loaded_kernel_module[]'}});
	#print "ARRLEN: $arrlen \n";
MAKECOLUMNS2:
	if (($arrlen % 5) == 0) {
		#warn colored("ARRLEN divisible by 5. \n", "yellow");
		for (my $i=0;$i<$arrlen;$i+=5) {
			print OUT "\t\t\t\t\t\t<tr><td>${$lynis_report_data{'loaded_kernel_module[]'}}[$i]</td><td>${$lynis_report_data{'loaded_kernel_module[]'}}[($i + 1)]</td><td>${$lynis_report_data{'loaded_kernel_module[]'}}[($i + 2)]</td><td>${$lynis_report_data{'loaded_kernel_module[]'}}[($i + 3)]</td><td>${$lynis_report_data{'loaded_kernel_module[]'}}[($i + 4)]</td></tr>\n";
		}
	} elsif (($arrlen % 4) == 0) {
		#print "ARRLEN divisible by 4. \n";
		for (my $i=0;$i<$arrlen;$i+=4) {
			print OUT "\t\t\t\t\t\t<tr><td>${$lynis_report_data{'loaded_kernel_module[]'}}[$i]</td><td>${$lynis_report_data{'loaded_kernel_module[]'}}[($i + 1)]</td><td>${$lynis_report_data{'loaded_kernel_module[]'}}[($i + 2)]</td><td>${$lynis_report_data{'loaded_kernel_module[]'}}[($i + 3)]</td></tr>\n";
		}
	} elsif (($arrlen % 3) == 0) {
		#print "ARRLEN divisible by 3. \n";
		for (my $i=0;$i<$arrlen;$i+=3) {
			print OUT "\t\t\t\t\t\t<tr><td>${$lynis_report_data{'loaded_kernel_module[]'}}[$i]</td><td>${$lynis_report_data{'loaded_kernel_module[]'}}[($i + 1)]</td><td>${$lynis_report_data{'loaded_kernel_module[]'}}[($i + 2)]</td></tr>\n";
		}
	} elsif (($arrlen % 2) == 0) {
		print "ARRLEN divisible by 2. \n";
	} else {
		if (&is_prime($arrlen)) { 
			print colored("Number ($arrlen) is prime. \n", "bold yellow") if (($verbose) and ($verbose > 1));
			$arrlen++;
			goto MAKECOLUMNS2;
		}
		die colored("ARRLEN appears to be number with a divisor larger than 5 or 1 ($arrlen) \n","bold red");
	}
	$lynis_report_data{'journal_oldest_bootdate'} = "&nbsp;" if ((!defined($lynis_report_data{'journal_oldest_bootdate'})) or ($lynis_report_data{'journal_oldest_bootdate'} eq ""));
	$lynis_report_data{'journal_contains_errors'} = 0 if ((!defined($lynis_report_data{'journal_contains_errors'})) or ($lynis_report_data{'journal_contains_errors'} eq ""));
	print OUT <<END;
					</table>
				</div>
			</div>
			<hr />
			<h3><a id="filesystem_info">filesystem/journalling info:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td>oldest boot date:</td><td>$lynis_report_data{'journal_oldest_bootdate'}</td>
						<td>journal errors:</td><td>$to_bool{$lynis_report_data{'journal_contains_errors'}}</td>\
					</tr>
					<tr>
						<td>journal disk size:</td><td>$lynis_report_data{'journal_disk_size'}</td>
						<td>last cordumps:</td><td>$lynis_report_data{'journal_coredumps_lastday'}</td>
					</tr>
					<tr>
END
	if ((exists($lynis_report_data{'file_systems_ext[]'})) and (ref($lynis_report_data{'file_systems_ext[]'}) eq "ARRAY")) {
		print OUT "\t\t\t\t\t\t<td>filesystems:</td><td>".join("\n", @{$lynis_report_data{'file_systems_ext[]'}})."</td>\n";
	} else {
		if (defined($lynis_report_data{'file_systems_ext[]'})) {
			print OUT "\t\t\t\t\t\t<td>filesystems:</td><td>$lynis_report_data{'file_systems_ext[]'}</td>\n";
		} else {
			print OUT "\t\t\t\t\t\t<td>filesystems:</td><td>&nbsp;</td>\n";
		}
	}
	if ((exists($lynis_report_data{'swap_partition[]'})) and (ref($lynis_report_data{'swap_partition[]'}) eq "ARRAY")) {
		print OUT "\t\t\t\t\t\t<td>swap partitions:</td><td>".join("\n", @{$lynis_report_data{'swap_partition[]'}})."</td>\n";
	} else {
		print OUT "\t\t\t\t\t\t<td>swap partitions:</td><td>$lynis_report_data{'swap_partition[]'}</td>\n";
	}
	$lynis_report_data{'journal_bootlogs'} = 0 if ((!defined($lynis_report_data{'journal_bootlogs'})) or ($lynis_report_data{'journal_bootlogs'} eq ""));
	print OUT <<END;
					</tr>
					<tr>
						<td>journal boot log found:</td><td>$to_bool{$lynis_report_data{'journal_bootlogs'}}</td>
						<td></td><td></td>
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
	} else { warn colored("Didn't find journal_meta_data object! \n", "yellow"); }
	print OUT <<END;
				</div>
			</div>
			<hr />
			<h3><a id="service_info">service info:</a></h3>
			<div class="content_subsection">
				<table>
END
	foreach my $prog ( sort qw( ntp_daemon mysql ssh_daemon dhcp_client arpwatch audit_daemon postgresql linux_auditd ) ) {
		if ((defined($lynis_report_data{$prog.'_running'})) and ($lynis_report_data{$prog.'_running'} ne "")) {
			print OUT "\n\n\n\n\n\n<tr><td>$prog running:</td><td>$to_bool{$lynis_report_data{$prog.'_running'}}</td></tr>\n";
		} else {
			print OUT "\n\n\n\n\n\n<tr><td>$prog running:</td><td>$to_bool{0}</td></tr>\n";
		}
	}
	print OUT "\t\t\t\t\t</table>\n";
	print OUT "\t\t\t<h4>daemon info:</h4>\n";
	print OUT "\t\t\t\t\t<table>\n";
	if ((exists($lynis_report_data{'pop3_daemon'})) and ($lynis_report_data{'pop3_daemon'} ne "")) {
		print OUT "\t\t\t\t\t\t<tr><td>pop3 daemon:</td><td>$lynis_report_data{'pop3_daemon'}</td></tr>\n";
	}
	if ((exists($lynis_report_data{'imap_daemon'})) and ($lynis_report_data{'imap_daemon'} ne "")) {
		print OUT "\t\t\t\t\t\t<tr><td>imap daemon:</td><td>$lynis_report_data{'imap_daemon'}</td></tr>\n";
	}
	if ((exists($lynis_report_data{'smtp_daemon'})) and ($lynis_report_data{'smtp_daemon'} ne "")) {
		print OUT "\t\t\t\t\t\t<tr><td>smtp daemon:</td><td>$lynis_report_data{'smtp_daemon'}</td></tr>\n";
	}
	if ((exists($lynis_report_data{'printing_daemon'})) and ($lynis_report_data{'printing_daemon'} ne "")) {
		print OUT "\t\t\t\t\t\t<tr><td>printing daemon:</td><td>$lynis_report_data{'printing_daemon'}</td></tr>\n";
	}
	if ((exists($lynis_report_data{'ntp_daemon'})) and ($lynis_report_data{'ntp_daemon'} ne "")) {
		print OUT "\t\t\t\t\t\t<tr><td>ntp daemon:</td><td>$lynis_report_data{'ntp_daemon'}</td></tr>\n";
	}
	if ((exists($lynis_report_data{'scheduler[]'})) and ($lynis_report_data{'scheduler[]'} ne "")) {
		print OUT "\t\t\t\t\t\t<tr><td>scheduler(s):</td><td>".join("<br />\n",@{$lynis_report_data{'scheduler[]'}})."</td></tr>\n";
	}
	if ((exists($lynis_report_data{'service_manager'})) and ($lynis_report_data{'service_manager'} ne "")) {
		print OUT "\t\t\t\t\t\t<tr><td>service manager:</td><td>$lynis_report_data{'service_manager'}</td></tr>\n";
	}
	if ((exists($lynis_report_data{'running_service_tool'})) and ($lynis_report_data{'running_service_tool'} ne "")) {
		print OUT "\t\t\t\t\t\t<tr><td>running service tool:</td><td>$lynis_report_data{'running_service_tool'}</td></tr>\n";
	}
	print OUT "\t\t\t\t\t</table>\n";
	if (exists($lynis_report_data{'running_service[]'})) {
		print OUT <<END;
				<h4>Running services:</h4>
				<ul>
END
		foreach my $svc ( @{$lynis_report_data{'running_service[]'}} ) {
			print OUT "\t\t\t\t\t<li>$svc</li>\n";
		}
		print OUT "\t\t\t\t\t</ul>\n";
	}
	print OUT <<END;
				<h5>ntp detail:</h5><a id="ntpDetailLink" href="javascript: toggle('ntpDetailLink','ntpDetailToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="ntpDetailToggle" style="display: none">
					<table>
						<tr>
							<td>ntp config found:</td><td>$to_bool{$lynis_report_data{'ntp_config_found'}}</td>
END
	if (exists($lynis_report_data{'ntp_config_file[]'})) {
		if (ref($lynis_report_data{'ntp_config_file[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t\t\t<td>ntp config file:</td><td>".join("<br />\n", @{$lynis_report_data{'ntp_config_file[]'}})."</td>\n";
		} else {
			#warn colored("ntp config file object not an array! \n", "yellow");
			print OUT "\t\t\t\t\t\t\t<td>ntp config file:</td><td>$lynis_report_data{'ntp_config_file[]'}</td>\n";
		}
	}
	print OUT <<END;
						</tr>
						<tr>
							<td>ntp version:</td><td>$lynis_report_data{'ntp_version'}</td>
END
	if (exists($lynis_report_data{'ntp_unreliable_peer[]'})) {
		if (ref($lynis_report_data{'ntp_unreliable_peer[]'}) eq 'ARRAY') {
			print OUT "\t\t\t\t\t\t\t<td>unreliable peers:</td><td>".join("<br />\n", @{$lynis_report_data{'ntp_unreliable_peer[]'}})."</td>";
		} else {
			print OUT "\t\t\t\t\t\t\t<td>unreliable peers:</td><td>$lynis_report_data{'ntp_unreliable_peer[]'}</td>";
		}
	} else {
		print OUT "\t\t\t\t\t\t\t<td></td><td></td>\n";
	}
	print OUT <<END;
						</tr>
						<tr><th colspan="4">NTP Config Type</th></tr>
						<tr>
							<td>startup:</td><td>$to_bool{$lynis_report_data{'ntp_config_type_startup'}}</td>
							<td>daemon:</td><td>$to_bool{$lynis_report_data{'ntp_config_type_daemon'}}</td>
						</tr>
						<tr>
							<td>scheduled:</td><td>$to_bool{$lynis_report_data{'ntp_config_type_scheduled'}}</td>
							<td>event based:</td><td>$to_bool{$lynis_report_data{'ntp_config_type_eventbased'}}</td>
						</tr>
					</table>
				</div>
				<br />
				<h5>nginx detail</h5>
				<table>
					<tr>
						<td>main config file:</td><td>$lynis_report_data{'nginx_main_conf_file'}</td>
END
	print OUT "\t\t\t\t\t<td>other config file(s):</td><td>".join("<br />\n", @{$lynis_report_data{'nginx_sub_conf_file'}})."</td>\n";
	print OUT <<END;
					</tr>
					<tr>
						<td>log file:</td><td>$lynis_report_data{'log_file'}</td>
						<td></td><td></td>
					</tr>
				</table>
END
	if (exists($lynis_report_data{'nginx_config_option'})) {
		print OUT "\t\t\t\t<h5>nginx config options:</h5><a id=\"nginxConfigLink\" href=\"javascript: toggle('nginxConfigLink', 'nginxConfigToggle');\">&gt;&nbsp;show&nbsp;&lt;</a>\n";
		print OUT "\t\t\t\t\t<div id=\"nginxConfigToggle\" style=\"display:none;\">\n";
		print OUT "\t\t\t\t\t<ul>\n";
		if (ref($lynis_report_data{'nginx_config_option'}) eq 'ARRAY') {
			foreach my $o ( @{$lynis_report_data{'nginx_config_option'}} ) { print OUT "\t\t\t\t\t\t<li>$o</li>\n"; }
		} else {
			if ((defined($lynis_report_data{'nginx_config_option'})) and ($lynis_report_data{'nginx_config_option'} ne "")) {
				print OUT "\t\t\t\t\t\t<li>$lynis_report_data{'nginx_config_option'}</li>\n";
			} else {
				print OUT "\t\t\t\t\t\t<li>N/A - Unable to detect nginx config </li>\n";
				warn colored("nginx config options opbject not an array! \n", "yellow");
				print Dumper($lynis_report_data{'nginx_config_option'});
			}
		}
		print OUT "\t\t\t\t\t</ul>\n";
	}
	print OUT <<END;
				</div><br />
END
	if (exists($lynis_report_data{'ssl_tls_protocol_enabled[]'})) {
		print OUT <<END;
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
		print OUT "\t\t\t\t</div><br />\n";
	}
	if (exists($lynis_report_data{'apache_version'})) {
		print OUT <<END;
					<h5>apache details:</h5>
					<a id="apacheDetailsLink" href="javascript:toggle('apacheDetailsLink','apacheDetailsToggle');">&gt; &nbsp; show &nbsp; &lt;</a>
					<div id="apacheDetailsToggle" style="display:none;">
						<table><tr><td>apache version:</td><td>$lynis_report_data{'apache_version'}</td></tr></table>
END
		if (exists($lynis_report_data{'apache_module[]'})) {
			print OUT <<END;
						<h5>apache modules found:</h5>
						<a id="apacheModulesLink" href="javascript:toggle('apacheModulesLink','apacheModulesToggle');">&gt; &nbsp; show &nbsp; &lt;</a>
						<div id="apacheModulesToggle" style="display:none;">
							<ul>
END
			if (ref($lynis_report_data{'apache_module[]'}) eq 'ARRAY') {
				foreach my $m ( sort @{$lynis_report_data{'apache_module[]'}} ) { print OUT "\t\t\t\t\t\t\t\t<li>$m</li>\n"; }
			} else {
				warn colored("apache module object not an array!\n", "yellow");
				print Dumper($lynis_report_data{'apache_module[]'});
			}
			print OUT "\t\t\t\t\t\t\t</ul>\n";
			print OUT "\t\t\t\t\t\t</div>\n";
		}
		print OUT "\t\t\t\t\t</div>\n";
	}	
	print OUT <<END;
				<h5>systemd detail:</h5><a id="systemdLink" href="javascript:toggle('systemdLink', 'systemdToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="systemdToggle" style="display:none;">
					<table>
						<tr>
							<td>systemd version:</td><td>$lynis_report_data{'systemd_version'}</td>
							<td>systemd status:</td><td>$lynis_report_data{'systemd_status'}</td>
						</tr>
						<tr>
							<td>systemd builtin components:</td><td colspan="3">$lynis_report_data{'systemd_builtin_components'}</td>
						</tr>
					</table>
END
	if (exists($lynis_report_data{'systemd_unit_file[]'})) {
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
			warn colored("systemd unit file object not an array! \n", "yellow");
		}
		print OUT <<END;
						</table>>
					</div>
END
	}
	if (exists($lynis_report_data{'systemd_unit_not_found[]'})) {
		print OUT <<END;
					<h5>systemd unit not found:</h5><a id="systemdUnitNotFoundLink" href="javascript:toggle('systemdUnitNotFoundLink','systemdUnitNotFoundToggle');">&gt; &nbsp; show &nbsp; &lt;</a>
					<div id="systemdUnitNotFoundToggle" style="display:none;">
						<ul>
END
		if (ref($lynis_report_data{'systemd_unit_not_found[]'})) {
			foreach my $unf ( sort @{$lynis_report_data{'systemd_unit_not_found[]'}} ) { print OUT "\t\t\t\t\t\t\t<li>$unf</li>\n"; }
		} else {
			warn colored("systemd unitnot found object not an array! \n", "yellow");
		}
		print OUT <<END; 
						</ul>
					</div>
END
	}
	if (exists($lynis_report_data{'systemd_service_not_found[]'})) {
	print OUT <<END;
					<h5>systemd service not found:</h5><a id="systemdServiceNotFoundLink" href="javascript:toggle('systemdServiceNotFoundLink','systemdServiceNotFoundToggle');">&gt; &nbsp; show &nbsp; &lt;</a>
					<div id="systemdServiceNotFoundToggle" style="display:none;">
						<ul>
END
		if (ref($lynis_report_data{'systemd_service_not_found[]'}) eq 'ARRAY') {
			foreach my $snf ( sort @{$lynis_report_data{'systemd_service_not_found[]'}} ) { print OUT "\t\t\t\t\t\t\t<li>$snf</li>\n"; }
		} else {
			warn colored("systemd service not found object not an array! \n", "yellow");
		}
		print OUT <<END;
						</ul>
					</div>
END
	}
	print OUT <<END;						
				</div>						
			</div>
			<hr />
			<h3><a id="installed_packages">Installed packages:</a></h3>
			<div class="content_subsection">
				<table>
					<tr>
						<td>Number of packages installed:</td><td>$lynis_report_data{'installed_packages'}</td>
						<td>Number of binaries found:</td><td>$lynis_report_data{'binaries_count'}</td>
					</tr>
				</table>
				<br />
				<a id="pkgLink" href="javascript: toggle('pkgLink', 'pkgContent');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="pkgContent" style="display: none">
					<table class="list">
END
	#print OUT "\t\t\t\t\t\t".join(" | ", @{$lynis_report_data{'installed_packages_array'}})."\n";
	$arrlen = scalar(@{$lynis_report_data{'installed_packages_array'}});
	#print "ARRLEN: $arrlen \n";
MAKECOLUMNS3:
	if (($arrlen % 5) == 0) {
		#print "ARRLEN divisible by 5. \n";
		for (my $i=0;$i<$arrlen;$i+=5) {
			print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'installed_packages_array'}}[$i]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 1)]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 2)]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 3)]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 4)]</td></tr>\n";
		}
	} elsif (($arrlen % 4) == 0) {
		#print "ARRLEN divisible by 4. \n";
		for (my $i=0;$i<$arrlen;$i+=4) {
			print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'installed_packages_array'}}[$i]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 1)]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 2)]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 3)]</td></tr>\n";
		}
	} elsif (($arrlen % 3) == 0) {
		#print "ARRLEN divisible by 3. \n";
		for (my $i=0;$i<$arrlen;$i+=3) {
			print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'installed_packages_array'}}[$i]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 1)]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 2)]</td></tr>\n";
		}
	} elsif (($arrlen % 2) == 0) {
		#print "ARRLEN divisible by 2. \n";
		for (my $i=0;$i<$arrlen;$i+=3) {
			print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'installed_packages_array'}}[$i]</td><td>${$lynis_report_data{'installed_packages_array'}}[($i + 1)]</td></tr>\n";
		}
	} else {
		if (&is_prime($arrlen)) { 
			print colored("Number ($arrlen) is prime. \n", "bold yellow"); 
			$arrlen++;
			goto MAKECOLUMNS3;
		}
		die colored("ARRLEN appears to be number with a divisor larger than 5 or 1 ($arrlen) \n", "bold red");
	}
	print OUT <<END;
					</table>
				</div>
			</div>
			<div id="footer">
				<hr />
				<p><a href="http://jigsaw.w3.org/css-validator/check/referer">
					<img style="border:0;width:88px;height:31px;"
						src="http://jigsaw.w3.org/css-validator/images/vcss"
						alt="Valid CSS!" />
				</a></p>
		</div>
	</body>
</html>

END

	close OUT or die colored("There was a problem closing the output file ($output): $! \n", "bold red");

	my @indexes = qw( lynis_version lynis_tests_done lynis_update_available license_key report_datetime_start report_datetime_end plugins_directory plugins_enabled finish report_version_major report_version_minor hostid hostid2 plugin_enabled_phase1[] hardening_index warning[] hostname domainname linux_kernel_version linux_config_file memory_size nameserver[] network_interface[] framework_grsecurity vm vmtype uptime_in_seconds linux_kernel_release os framework_selinux uptime_in_days os_fullname default_gateway[] cpu_nx cpu_pae linux_version os_version network_ipv6_address[] boot_loader suggestion[] manual manual[] linux_version cpu_pae cpu_nx network_ipv4_address[] network_mac_address[] os_name os_kernel_version os_kernel_version_full firewall_installed max_password_retry password_max_days password_min_days pam_cracklib password_strength_tested minimum_password_length package_audit_tool package_audit_tool_found vulnerable_packages_found firewall_active firewall_software[] firewall_software auth_failed_logins_logged authentication_two_factor_enabled memory_units default_gateway authentication_two_factor_required malware_scanner_installed file_integrity_tool_installed file_integrity_tool_installed pam_module[] ids_ips_tooling[] ipv6_mode ipv6_only name_cache_used ldap_pam_enabled ntp_daemon_running mysql_running ssh_daemon_running dhcp_client_running arpwatch_running running_service[] audit_daemon_running installed_packages binaries_count installed_packages_array crond_running network_listen_port[] firewall_empty_ruleset automation_tool_present automation_tool_running[] file_integrity_tool ldap_auth_enabled password_max_l_credit password_max_u_credit password_max_digital_credit password_max_other_credit loaded_kernel_module[] plugin_directory package_manager[] linux_kernel_io_scheduler[] linux_kernel_type details[] available_shell[] locate_db smtp_daemon pop3_daemon ntp_daemon imap_daemon printing_daemon boot_service[] boot_uefi_boot_secure linux_default_runlevel boot_service_tool boot_uefi_booted systemctl_exit_code min_password_class session_timeout_enabled compiler_installed real_user[] home_directory[] swap_partition[] filesystem_ext[] journal_disk_size journal_coredumps_lastday journal_oldest_bootdate journal_contains_errors swap_partition[] file_systems_ext[] test_category test_group scheduler[] journal_meta_data boot_uefi_booted_secure service_manager running_service_tool binary_paths valid_certificate[] cronjob[] log_directory[] open_logfile[] journal_bootlogs log_rotation_tool log_rotation_config_found auditor deleted_file[] vulnerable_package[] malware_scanner[] file_integrity_tool[] plugin_firewall_iptables_list linux_amount_of_kernels ntp_config_type_startup ntp_config_type_scheduled ntp_config_type_eventbased ntp_config_type_daemon ntp_config_file[] ntp_config_found ntp_version ntp_unreliable_peer[] postgresql_running linux_auditd_running linux_kernel_io_scheduler nginx_main_conf_file log_file nginx_sub_conf_file nginx_config_option ssl_tls_protocol_enabled[] systemd systemd_builtin_components systemd_version systemd_status plugin_processes_allprocesses usb_authorized_default_device[] systemd_unit_file[] systemd_unit_not_found[] systemd_service_not_found[] resolv_conf_search_domain[] expired_certificate[] compiler[] fail2ban_config fail2ban_enabled_service[] apache_version apache_module[] );
	foreach my $idx ( sort @indexes ) {
		delete($lynis_report_data{$idx});
	}

	if ($pdf) {
		my $htmlobj = new HTML::HTMLDoc();
		$htmlobj->set_input_file($htmldoc);
		my $pdfdoc = $htmlobj->generate_pdf();
		$pdfdoc->to_file($output);
		my $errs = system("rm -f $htmldoc");
		if ($verbose) { print "Clean up return code: $errs \n"; }
	}	
}

print Dumper(\%lynis_report_data);

###############################################################################
# subs
###############################################################################
sub usage {
	print <<END;

$0 -h|--help -v|--verbose -E|--excel -o|--output

Where:

-h|--help			Display this useful message, then exit.
-v|--verbose		Display more detailed output.  This is typically used for
					debugging, but may provide insight when running into problems.
-E|--excel			Output the report in Microsoft Excel binary format.  This
					options is not yet implemented (NYI).
-o|--output			Specifies the output file to print the report to.

END
	exit 0;
}

sub is_prime {
	my $num = shift(@_);

	if ($num < 2 ) { return 0; }
	if ($num == 2) { return 1; }
	else {
		for (my$i=2;$i<sqrt($num);$i++) {
			if ($num % $i == 0) {
				return 0;
			}
		}
		return 1;
	}
}

sub dedup_array {
	my $aryref = shift;
	my %hash;

	foreach my $ele ( @{$aryref} ) { $hash{$ele}++; }
	return sort keys(%hash);
}

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
