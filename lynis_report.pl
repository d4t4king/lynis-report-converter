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
			div#content_section {margin: 0 10% 0 10%;}
			div.content_subsection {margin: 0 5% 0 5%;}
			table {border-collapse: collapse; border: 1px solid white;}
			table#lynis_plugins_table {width:100%;}
			td {padding:2px 5px 2px 5px;}
			td.good {background-color: #006400; color: #ffffff; font-weight: bold;}
			td.fair {background-color: #ffd700; color: #000000; font-weight: bold;}
			td.poor {background-color: #ffa500; color: #000000; font-weight: bold;}
			td.dismal {background-color: #ff0000; color: #000000; font-weight: bold;}
			span.title_shrink {font-size: 75%;}
		</style>
	</head>
	<body>
		<div id="content_section">
			<h1>lynis Asset Report</h1>
			<h2><span class="title_shrink">created by</span> lynis_report</h2>
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
		print OUT "\t\t\t\t\t<tr><td>$sug_id</td><td>$sug_desc</td><td>$sug_sev</td><td>$sug_f4</td></tr>\n";
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
						<td>license key:</td><td>$lynis_report_data{'license_key'}</td>
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
						<td>resolv.conf domain:</td><td>$lynis_report_data{'resolv_conf_domain'}</td>
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
END
print OUT "\t\t\t\t\t<tr><td>network interfaces:</td><td>".join("<br />\n", @{$lynis_report_data{'network_interface[]'}})."</td><td>ipv4 addresses:</td><td>".join("<br />\n", @{$lynis_report_data{'network_ipv4_address[]'}})."</td><td>ipv6 addresses:</td><td>".join("<br />\n", @{$lynis_report_data{'network_ipv6_address[]'}})."</td></tr>\n";
print OUT <<END;
					<tr>
						<td></td><td></td>
						<td></td><td></td>
						<td>uptime (days):</td><td>$lynis_report_data{'uptime_in_days'}</td>
					</tr>
					<tr>
						<td>vm:</td><td>$to_bool{$lynis_report_data{'vm'}}</td>
						<td>vm_type:</td><td>$lynis_report_data{'vmtype'}</td>
						<td>uptime (secs):</td><td>$lynis_report_data{'uptime_in_seconds'}</td></tr>
				</table>
			</div>
			<hr />
			<h3><a name="network_info">network info:</a></h3>
			<div class="content_subsection">
				<table border="1">
					<tr>
						<td colspan="2">Default Gateway</td><td colspan="2">$lynis_report_data{'default_gateway[]'}</td>
					</tr>
					<tr>
						<td>IPv6 Mode:</td><td>$lynis_report_data{'ipv6_mode'}</td>
						<td>IPv6 Only:</td><td>$to_bool{$lynis_report_data{'ipv6_only'}}</td>
					</tr>
					<tr>
END
print OUT "\t\t\t\t\t\t<td>MAC Address:</td><td>".join("<br />\n", @{$lynis_report_data{'network_mac_address[]'}})."</td>\n";
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
						<td>IDS/IPS Tooling</td><td>$lynis_report_data{'ids_ips_tooling[]'}</td>
					</tr>
					<tr>
						<td>LDAP PAM Module Enabled:</td><td>$to_bool{$lynis_report_data{'ldap_pam_enabled'}}</td>
						<td>Two-Factor Authentication Enabled:</td><td>$to_bool{$lynis_report_data{'authentication_two_factor_enabled'}}</td>
						<td>Two-Factor Authentication Required:</td><td>$to_bool{$lynis_report_data{'authentication_two_factor_required'}}</td>
						<td>Failed Logins Logged:</td><td>$lynis_report_data{'auth_failed_logins_logged'}</td>
					</tr>
					<tr>
						<td>Minimum Password Length:</td><td>$lynis_report_data{'minimum_password_length'}</td>
						<td>Maximum Password Days:</td><td>$lynis_report_data{'password_max_days'}</td>
						<td>Minimum Password Days:</td><td>$lynis_report_data{'password_min_days'}</td>
						<td>Maximum Password Retries:</td><td>$lynis_report_data{'max_password_retry'}</td>
					</tr>
					<tr>
						<td>PAM Cracklib Found:</td><td>$to_bool{$lynis_report_data{'pam_cracklib'}}</td>
						<td>Password Strength Tested:</td><td>$to_bool{$lynis_report_data{'password_strength_tested'}}</td>
						<td>Malware Scanner Installed:</td><td>$to_bool{$lynis_report_data{'malware_scanner_installed'}}</td>
						<td>File Integrity Tool Installed:</td><td>$to_bool{$lynis_report_data{'file_integrity_tool_installed'}}</td>
					</tr>
					<tr>
					</tr>
				</table>
				<h4>PAM Modules:</h4>
				<table border="1">
END
for (my $i=0;$i<scalar(@{$lynis_report_data{'pam_module[]'}});$i+=4) {
	print OUT "\t\t\t\t\t<tr><td>${$lynis_report_data{'pam_module[]'}}[$i]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 1)]</td>";
	print OUT "<td>${$lynis_report_data{'pam_module[]'}}[($i + 2)]</td><td>${$lynis_report_data{'pam_module[]'}}[($i + 3)]</td></tr>\n";
}
print OUT <<END;
				</table>
			</div>
			<hr />
			<h4><a name="kernel_info">kernel info:</a></h4>
			<div class="content_subsection">
				<table border="1">
					<tr>
						<td>full kernel version:</td><td>$lynis_report_data{'os_kernel_version_full'}</td>
					</tr>
					<tr>
						<td>kernel version:</td><td>$lynis_report_data{'linux_kernel_version'}</td>
						<td>kernel release version:</td><td>$lynis_report_data{'linux_kernel_release'}</td>
					</tr>
				</table>
			</div>
		</div>
	</body>
</html>

END

close OUT or die colored("There was a problem closing the output file ($output): $! \n", "bold red");

my @indexes = qw( lynis_version lynis_tests_done lynis_update_available license_key report_datetime_start report_datetime_end plugins_directory plugins_enabled finish report_version_major report_version_minor hostid hostid2 plugin_enabled_phase1[] hardening_index warning[] hostname domainname linux_kernel_version linux_config_file memory_size nameserver[] network_interface[] framework_grsecurity vm vmtype uptime_in_seconds linux_kernel_release os framework_selinux uptime_in_days resolv_conf_domain os_fullname default_gateway[] cpu_nx cpu_pae linux_version os_version network_ipv6_address[] boot_loader suggestion[] manual manual[] linux_version cpu_pae cpu_nx network_ipv4_address[] network_ipv6_address[] network_interfaces[] os_name os_kernel_version os_kernel_version_full firewall_installed max_password_retry password_max_days password_min_days pam_cracklib password_strength_tested minimum_password_length package_audit_tool package_audit_tool_found vulnerable_packages_found firewall_active firewall_software auth_failed_logins_logged authentication_two_factor_enabled memory_units default_gateway authentication_two_factor_required malware_scanner_installed file_integrity_tool_installed file_integrity_tool_installed pam_module[] ids_ips_tooling[] ipv6_mode ipv6_only network_mac_address[] name_cache_used ldap_pam_enabled );
foreach my $idx ( sort @indexes ) {
	delete($lynis_report_data{$idx});
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
