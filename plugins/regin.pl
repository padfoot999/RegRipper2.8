#-----------------------------------------------------------
# regin.pl
#
# History:
#  20141124 - created
#
# References:
#  http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/regin-analysis.pdf
#  https://securelist.com/files/2014/11/Kaspersky_Lab_whitepaper_Regin_platform_eng.pdf
# 
# copyright 2014 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package regin;
use strict;

my %config = (hive          => "System",
							hivemask      => 4,
							output        => "report",
							category      => "malware",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 31,  #XP - Win7
              version       => 20141124);

sub getConfig{return %config}
sub getShortDescr {
	return "Detect Regin";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my %files;

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching regin v.".$VERSION);
	::rptMsg("regin v.".$VERSION); # banner
  ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner 
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
# First thing to do is get the ControlSet00x marked current...this is
# going to be used over and over again in plugins that access the system
# file
	my ($current,$ccs);
	my $key_path = 'Select';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		$current = $key->get_value("Current")->get_data();
		$ccs = "ControlSet00".$current;
		
# Symantec Whitepaper: Stage 2		
# Kaspersky calls this Stage 1
		$key_path = $ccs."\\Control\\Class\\{4F20E605-9452-4787-B793-D0204917CA58}";
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg("Possible Regin Stage 2 found in ".$key_path);
		}

# Symantec Whitepaper: Stage 3		
		$key_path = $ccs."\\Control\\Class\\{4F20E605-9452-4787-B793-D0204917CA5A}";
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg("Possible Regin Stage 3 found in ".$key_path);
		}

# Kaspersky Whitepaper: Stage 2, 32-bit	
		$key_path = $ccs."\\Control\\Class\\{39399744-44FC-AD65-474B-E4DDF-8C7FB97}";
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg("Possible Regin Stage 2 found in ".$key_path);
		}

# Kaspersky Whitepaper: Stage 2, 32-bit			
		$key_path = $ccs."\\Control\\Class\\{3F90B1B4-58E2-251E-6FFE-4D38C5631A04}";
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg("Possible Regin Stage 2 found in ".$key_path);
		}
		
# Kaspersky Whitepaper: Stage 3 (?)		
		$key_path = $ccs."\\Control\\Class\\{9B9A8ADB-8864-4BC4-8AD5-B17DFDBB9F58}";
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg("Possible Regin Stage 2 found in ".$key_path);
		}		
				
# Symantec Whitepaper: Stage 2, version 2 only (?)		
		$key_path = $ccs."\\Control\\RestoreList\\VideoBase";
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg("Possible Regin Stage 2 found in ".$key_path);
		}
	}
}
1;