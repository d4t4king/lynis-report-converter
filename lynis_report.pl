#!/usr/bin/perl -w

use strict;
use warnings;
use feature qw( switch );
no if $] ge '5.018', warnings => "experimental::smartmatch";
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

if ($help) { &usage; }

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

@{$lynis_report_data{'automation_tool_running[]'}} = &dedup_array(@{$lynis_report_data{'automation_tool_running[]'}}) if (ref($lynis_report_data{'automation_tool_running[]'}) eq 'ARRAY');

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
			div#content_section {margin: 0 10% 0 10%;}
			div.content_subsection {margin: 0 5% 0 5%;}
			div.collapsable {display: none;}
			table {border-collapse: collapse; border: 1px solid white;}
			table#lynis_plugins_table {width:100%;}
			td {padding:2px 5px 2px 5px;}
			td.good {background-color: #006400; color: #fff; font-weight: bold;}
			td.fair {background-color: #ffd700; color: #000; font-weight: bold;}
			td.poor {background-color: #ffa500; color: #000; font-weight: bold;}
			td.dismal {background-color: #ff0000; color: #000; font-weight: bold;}
			td.tf_bad {background-color:#ff0000; colore: #000; font-weight: bold;}
			td.tf_good {background-color: #006400; color: #fff; font_weight: bold;}
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
		<script language="javascript">
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
			<table border="1">
				<tr>
					<td><a href="#lynis_info">lynis info</a></td><td><a href="#host_info">host info</a></td>
					<td><a href="#network_info">network info</a></td><td><a href="#security_info">security Info</a></td>
				</tr>
			</table>
			<hr />
			<h3>host findings:</h3>
			<table border="1"><tr><td>hardening index:</td>
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

print OUT "\t\t\t</tr></table>\n";
if (!exists($lynis_report_data{'warning[]'})) {
	print OUT "<h4>warnings (0):</h4>\n";
} else {
	print OUT "<h4>warnings (".scalar(@{$lynis_report_data{'warning[]'}})."):</h4>\n";
}
print OUT <<END;
			<div class="content_subsection">
				<table border="1">
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
		print OUT "\t\t\t\t\t<tr><td>$sug_id</td>";
		print OUT "<td>$sug_desc</td>";
		print OUT "<td>".($sug_sev ? $sug_sev : "&nbsp;")."</td>";
		print OUT "<td>".($sug_f4 ? $sug_f4 : "&nbsp;")."</td></tr>\n";
	}
}
print OUT <<END;
				</table>
			</div>
			<h4>manual checks:</h4>
			<ul>
END
if ((exists($lynis_report_data{'manual[]'})) and (scalar(@{$lynis_report_data{'manual[]'}}) > 0)) {
	foreach my $man ( sort @{$lynis_report_data{'manual[]'}} ) {
		#print Dumper($man);
		chomp($man);
		print OUT "<li>$man</li>\n";
	}
}

# It's easier to move stuff around if there is one cell (or cell group) per libe for the tables.  Maybe this
# isn't ideal HTML writing, but it makes sense when writing the tool.
print OUT <<END;
			</ul>
			<hr />
			<h3><a name="lynis_info">lynis info:</a></h3>
			<div class="content_subsection">
				<table border="1">
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
						<td>number of plugins enabled:</td><td>$lynis_report_data{'plugins_enabled'}</td>
						<td>plugin directory:</td><td>$lynis_report_data{'plugin_directory'}</td>
					</tr>
					<tr>
END

print OUT "\t\t\t\t\t\t<td>phase 1 plugins enabled:</td><td colspan=\"3\">\n";
print OUT "\t\t\t\t\t\t\t<table border=\"1\" id=\"lynis_plugins_table\">\n";
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
				</table>
			</div>
			<hr />
			<h3><a name="host_info">host info:</a></h3>
			<div class="content_subsection">
				<table border="1">
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
print OUT <<END;
						<td>locate db:</td><td>$lynis_report_data{'locate_db'}</td>
						<td>uptime (days):</td><td>$lynis_report_data{'uptime_in_days'}</td>
					</tr>
					<tr>
						<td>vm:</td><td>$lynis_report_data{'vm'}</td>
END
if ((defined($lynis_report_data{'vmtype'})) and ($lynis_report_data{'vmtype'} ne "")) {
	print OUT "\t\t\t\t\t\t<td>vm_type:</td><td>$lynis_report_data{'vmtype'}</td>\n";
} else{
	print OUT "\t\t\t\t\t\t<td>vm_type:</td><td>&nbsp;</td>\n";
}
print OUT <<END;
						<td>uptime (secs):</td><td>$lynis_report_data{'uptime_in_seconds'}</td>
					</tr>
				</table>
			</div>
			<hr />
			<h3><a name="network_info">network info:</a></h3>
			<div class="content_subsection">
				<table border="1">
					<tr>
						<td>IPv6 Mode:</td><td>$lynis_report_data{'ipv6_mode'}</td>
						<td>IPv6 Only:</td><td>$to_bool{$lynis_report_data{'ipv6_only'}}</td>
					</tr>
END
print OUT "\t\t\t\t\t<tr><td colspan=\"2\">network interfaces:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'network_interface[]'}})."</td></tr>\n";
print OUT "\t\t\t\t\t<tr><td colspan=\"2\">ipv4 addresses:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'network_ipv4_address[]'}})."</td></tr>\n";
print OUT "\t\t\t\t\t<tr><td colspan=\"2\">ipv6 addresses:</td><td colspan=\"2\">".join("<br />\n", @{$lynis_report_data{'network_ipv6_address[]'}})."</td></tr>\n";
print OUT "\t\t\t\t\t<tr><td colspan=\"2\">Default Gateway</td><td colspan=\"2\">$lynis_report_data{'default_gateway[]'}</td></tr>\n";
print OUT <<END;
					<tr>
END
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
					</td>
				</table>
				<h4>Open Ports:</h4>
				<table border="1">
					<tr><td>IP Address</td><td>Port</td><td>Protocol</td><td>Daemon/Process</td><td>???</td></tr>
END

foreach my $obj ( sort @{$lynis_report_data{'network_listen_port[]'}} ) {
	my ($ipp,$proto,$daemon,$dunno) = split(/\|/, $obj);
	my ($ip,$port);
	my $colon_count = grep(/\:/, split(//, $ipp));
	if ($colon_count > 1) {
		# must be an IPv6 address;
		my @parts = split(/\:/, $ipp);
		$port = pop(@parts);
		$ip = join(":", @parts);
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
			<h3><a name="security_info">security info:</a></h3>
			<div class="content_subsection">
				<table border="1">
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
if (exists($lynis_report_data{'ids_ips_tooling[]'})) {
	print OUT "\t\t\t\t\t\t<td>IDS/IPS Tooling</td><td>$lynis_report_data{'ids_ips_tooling[]'}</td>\n";
} else {
	print OUT "\t\t\t\t\t\t<td>IDS/IPS Tooling</td><td>&nbsp;</td>\n";
}
print OUT <<END;
						<td></td><td></td>
						<td></td><td></td>
					</tr>
				</table>
				<h4>PAM Modules:</h4><a id="pamModLink" href="javascript:toggle('pamModLink', 'pamModToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="pamModToggle" style="display: none">
					<table border="0">
END
my $arrlen = scalar(@{$lynis_report_data{'pam_module[]'}});
#print "ARRLEN: $arrlen \n";
if (($arrlen % 5) == 0) {
	#print "ARRLEN divisible by 5. \n";
	for (my $i=0;$i<$arrlen;$i+=5) {
		print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'pam_module[]'}}[$i]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 1)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 2)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 3)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 4)]</td></tr>\n";
	}
} elsif (($arrlen % 4) == 0) {
	print "ARRLEN divisible by 4. \n";
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
	die colored("ARRLEN appears to be number with a divisor larger than 5 or 1 ($arrlen) \n", "bold red");
}
print OUT <<END;
					</table>
				</div>
			</div>
			<hr />
			<h3><a name="kernel_info">kernel info:</a></h3>
			<div class="content_subsection">
				<table border="1">
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
						<td></td><td></td>
					</tr>
				</table>
				<h4>kernel modules loaded:</h4><a id="kernelModLink" href="javascript:toggle('kernelModLink', 'kernelModToggle');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="kernelModToggle" style="display: none">
					<table border="0">
END
$arrlen = scalar(@{$lynis_report_data{'loaded_kernel_module[]'}});
#print "ARRLEN: $arrlen \n";
if (($arrlen % 5) == 0) {
	print "ARRLEN divisible by 5. \n";
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
	die colored("ARRLEN appears to be number with a divisor larger than 5 or 1 ($arrlen) \n","bold red");
}
print OUT <<END;
					</table>
				</div>
			</div>
			<hr />
			<h3><a name="service_info">service info:</a></h3>
			<div class="content_subsection">
				<!-- <table border="1">
END
foreach my $prog ( sort qw( ntp_daemon mysql ssh_daemon dhcp_client arpwatch audit_daemon ) ) {
	if ((defined($lynis_report_data{$prog.'_running'})) and ($lynis_report_data{$prog.'_running'} ne "")) {
		print OUT "\n\n\n\n\n\n<tr><td>$prog running:</td><td>$to_bool{$lynis_report_data{$prog.'_running'}}</td></tr>\n";
	} else {
		print OUT "\n\n\n\n\n\n<tr><td>$prog running:</td><td>$to_bool{0}</td></tr>\n";
	}
}
print OUT "\t\t\t\t\t</table> -->\n";
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
			</div>
			<hr />
			<h3><a name="installed_packages">Installed packages:</a></h3>
			<div class="content_subsection">
				<table border="1">
					<tr>
						<td>Number of packages installed:</td><td>$lynis_report_data{'installed_packages'}</td>
						<td>Number of binaries found:</td><td>$lynis_report_data{'binaries_count'}</td>
					</tr>
				</table>
				<br />
				<a id="pkgLink" href="javascript: toggle('pkgLink', 'pkgContent');">&gt;&nbsp;show&nbsp;&lt;</a>
				<div id="pkgContent" style="display: none">
					<table border="0">
END
#print OUT "\t\t\t\t\t\t".join(" | ", @{$lynis_report_data{'installed_packages_array'}})."\n";
$arrlen = scalar(@{$lynis_report_data{'installed_packages_array'}});
#print "ARRLEN: $arrlen \n";
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
	die colored("ARRLEN appears to be number with a divisor larger than 5 or 1 ($arrlen) \n", "bold red");
}
print OUT <<END;
					</table>
				</div>
			</div>
		</div>
	</body>
</html>

END

close OUT or die colored("There was a problem closing the output file ($output): $! \n", "bold red");

my @indexes = qw( lynis_version lynis_tests_done lynis_update_available license_key report_datetime_start report_datetime_end plugins_directory plugins_enabled finish report_version_major report_version_minor hostid hostid2 plugin_enabled_phase1[] hardening_index warning[] hostname domainname linux_kernel_version linux_config_file memory_size nameserver[] network_interface[] framework_grsecurity vm vmtype uptime_in_seconds linux_kernel_release os framework_selinux uptime_in_days resolv_conf_domain os_fullname default_gateway[] cpu_nx cpu_pae linux_version os_version network_ipv6_address[] boot_loader suggestion[] manual manual[] linux_version cpu_pae cpu_nx network_ipv4_address[] network_mac_address[] os_name os_kernel_version os_kernel_version_full firewall_installed max_password_retry password_max_days password_min_days pam_cracklib password_strength_tested minimum_password_length package_audit_tool package_audit_tool_found vulnerable_packages_found firewall_active firewall_software[] firewall_software auth_failed_logins_logged authentication_two_factor_enabled memory_units default_gateway authentication_two_factor_required malware_scanner_installed file_integrity_tool_installed file_integrity_tool_installed pam_module[] ids_ips_tooling[] ipv6_mode ipv6_only name_cache_used ldap_pam_enabled ntp_daemon_running mysql_running ssh_daemon_running dhcp_client_running arpwatch_running running_service[] audit_daemon_running installed_packages binaries_count installed_packages_array crond_running network_listen_port[] firewall_empty_ruleset automation_tool_present automation_tool_running[] file_integrity_tool ldap_auth_enabled password_max_l_credit password_max_u_credit password_max_digital_credit password_max_other_credit loaded_kernel_module[] plugin_directory package_manager[] linux_kernel_io_scheduler[] linux_kernel_type details[] available_shell[] locate_db );
foreach my $idx ( sort @indexes ) {
	delete($lynis_report_data{$idx});
}
#print Dumper(\%lynis_report_data);

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

sub dedup_array {
	my @ary = shift;
	my %hash;

	foreach my $ele ( @ary ) { $hash{$ele}++; }
	return keys(%hash);
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
