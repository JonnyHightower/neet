##########################################################################
#
#    Neet: Network discovery, enumeration and security assessment tool
#    Copyright (C) 2008-2014 Jonathan Roach
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    Contact: jonnyhightower [at] funkygeek.com
#
##########################################################################

# ServiceDiscovery.pm

# The SDM for Neet. Finds and classifies services
# Jonathan Roach
# January 21 2008
# Last update 4/11/2011

package Neet::SDM;

sub new {
	my $pkg=shift();
	my $MainScan=shift();
	my $PARAMS=shift();
	my $threadID=shift();
	my %engine;
	my %scanstatus;
	$engine{'MainScan'}=$MainScan;
	$engine{'ThreadID'}=$threadID;
	$engine{'StatusFile'}=".scanstatus";
	($engine{'Protocol'},$engine{'Target'},$engine{'TargetType'},$engine{'Interface'},$engine{'TargetID'},$engine{'CurrentRange'},$engine{'Phase'})=split ":", $PARAMS;
	my $object=\%engine;
	bless $object, $pkg;
	return $object;
}

sub ScanHost {
	my $self=shift();
	my $MainScan=$$self{'MainScan'};
	my $Protocol=$$self{'Protocol'};
	my $UProtocol=uc($Protocol);
	my $Log=$MainScan->Log;
	my $Config=$MainScan->Config;
	my $Phase=shift();
	my $Ports=$$self{'CurrentRange'};
	my $Target=$$self{'Target'};
	my $Interface=$$self{'Interface'};
	my $TargetType=$$self{'TargetType'};
	my $SpeedProfile=$TargetType;
	my $outputDir=$Target;
	my $outputXML="${outputDir}/raw/portscan.${Protocol}.${Phase}.xml";
	my $outputGrep="${outputDir}/raw/portscan.${Protocol}.${Phase}.gnmap";
	my $outputTXT="${outputDir}/raw/portscan.${Protocol}.${Phase}.txt";
	my $ServiceNames=$MainScan->ResourceDirectory . "/" . $Config->GetVal("ServiceTranslations");
	my $ThreadID=$$self{'ThreadID'};
	my $OSGuessFile="${outputDir}/.osguess.dat";
	$$self{'StatusFile'}="${outputDir}/" . $$self{'StatusFile'};

	# Don't bother if we've worked out this host is dead
	if ($MainScan->IsHostDown($Target)){
		$Log->Info("SDM - Thread $ThreadID: $Target down [$TargetType $Interface]: SKIPPED Phase $Phase Proto $Protocol range $Ports\n") if ($MainScan->Debug);
		return 0;
	}
	# Don't bother if the user (or some other mechanism) has cancelled the host
	if ($MainScan->IsHostCancelled($Target)){
		$Log->Info("SDM - Thread $ThreadID: $Target cancelled [$TargetType $Interface]: SKIPPED Phase $Phase Proto $Protocol range $Ports\n") if ($MainScan->Debug);
		return 0;
	}

	# In case a previous thread left us in the wrong place!
	my $issuesFile="issues.txt";

	$Log->Info("SDM - Thread $ThreadID Port scanning $Target [$TargetType $Interface] Phase $Phase Proto $Protocol range $Ports\n") if ($MainScan->Debug);

	mkdir "services";
	mkdir "$outputDir";
	mkdir "${outputDir}/raw";

	$MainScan->SetStatValue("${outputDir}/hostInfo.txt","ReachedBy","$Interface");

	# Global results
	my ($RPCInfo,@openPorts,@openUdpPorts,@filteredUdpPorts,%OSPGuess,%OSGuess); my $osindex=0;

	if (-f $OSGuessFile){
		%OSGuess=%{Storable::retrieve("$OSGuessFile")};
		$osindex=$OSGuess{'index'}{'0'};
	} else {
		$OSGuess{'index'}{'0'}=$osindex
	}

	# Phase-specific flags
	my ($udpscanned,$tcpscanned,$svccount)=(0,0,0);

	my $error=1;

	# See if the host responds to ICMP echo. This can be used by the limit-uptime option
	if (! -f "${outputDir}/raw/echoRequest.txt"){
		$MainScan->System("ping -W3 -c2 -n $Target > \"${outputDir}/raw/echoRequest.txt\" 2>&1");
	}

	if ($Protocol eq "tcp"){
		# *************
		# TCP Port Scan
		if (!$self->IsScanComplete("tcpscan")){
			# Construct the command line
			$_TCPScan=$MainScan->getPath("nmap") . " -e $Interface ";
			if ($MainScan->ConnectScan){
				$_TCPScan .= "-sT";
			} else {
				$_TCPScan .= "-sS";
			}
			$_TCPScan .= " $Target -n -T \"" . $Config->GetVal("Speeds.$TargetType.nmap.tcp." . $MainScan->Speed) . "\"";
			my $DiscoType=" -PN";
			if ($MainScan->PingScan) {
				$DiscoType = " -PE";
			}
			if ("$TargetType" eq "local"){
				$DiscoType = " -PR";
			}
			if ($MainScan->IsHostVPN($Target)){
				$SpeedProfile="vpn";
			}
			$_TCPScan .= $DiscoType;

			# If we have discovered ports by RPC Info, don't bother port scanning them
			if (-f "${outputDir}/rpcinfo.txt"){
				$RPCInfo=RPCInfo->new("${outputDir}/rpcinfo.txt");
				my $PortSpec=PortRange->new($Ports);
				if ($RPCInfo){
					for my $rpcport ($RPCInfo->ListTCPPorts){
						$PortSpec->Exclude($rpcport);
					}
				}
				$Ports=$PortSpec->RangeSpec;
			}

			my $TCPcommand=$_TCPScan . " -p $Ports -oX $outputXML -oG $outputGrep > $outputTXT";

			# Now run the command using the system() wrapper in MainScan. It is essential to
			# store the return code in the variable "$error". $error should ALWAYS be 0 if
	    		# the scan completed OK, or a positive integer otherwise.
			$error=$MainScan->System("$TCPcommand 2>/dev/null");

			if (!$error){
				# Parse the results
				my $np = JR::Parsers::Nmap->new();
    				if ($MainScan->WasPaused){
		    			$self->CleanUp;
			    		return 0;
				}
				$np->parsefile("$outputXML");

				my $host=$np->get_host($Target);

				if ($host){
					my $status=$host->status;
					if ($status eq "up"){
						my $evidenceOfLife=0;
						if (my $_MAC=$host->mac_addr){
							$evidenceOfLife=1;
							my $_mfr=$host->mac_vendor;
							if (open(MAC,">${outputDir}/mac.txt")){
								print MAC "$_MAC";
								print MAC " $_mfr" if ($_mfr);
								print MAC "\n";
								close MAC;
							}
						}

						for my $_port ($host->tcp_ports('open')){
							push @openPorts, $_port;
						}

						# List the open ports
						if ($#openPorts >=0 ){
							$evidenceOfLife=1;
							if (open(PF,">>${outputDir}/tcpports.txt")){
								for my $_port (@openPorts){
									my $svc=$host->tcp_service($_port);
									my $_name=$svc->name;
									print PF "$_port ";
									print PF "$_name" if ($_name);
									print PF "\n";
								}
								close PF;
							}
						}

						if (($TargetType eq "local") || ($MainScan->PingScan) || $evidenceOfLife){
							# We can be quite sure of this as it must have responded to ARP or ICMP/TCP.
							$MainScan->SetListItem("liveHosts.txt",$Target);
						}# else {
							# Not so sure. Nmap thinks it was up but it was told not to do any discovery.
							# Don't quote it as being live just yet.
						#}

					} else {
						# Nmap thinks this host is down
						if (($TargetType) eq "local" || ($MainScan->PingScan)) {
							# We consider it definitely down because it didn't respond to ARP or ICMP/TCP ping
							$MainScan->SetHostDown($Target);
							$MainScan->System("/bin/rm -rf $outputDir");
							$self->CleanUp;
							return 0;
						}
						# Otherwise we give it the benefit of the doubt
					}
				} else {
					# What to do here? No host object. Treat it like it's down.
					if (($TargetType eq "local") || ($MainScan->PingScan)){
						if (!$MainScan->TargetLive($Target)){
							# We consider it down because it didn't respond to ARP or ICMP
							$MainScan->SetHostDown($Target);
							$MainScan->System("/bin/rm -rf $outputDir");
						} else {
							$Log->Error ("SDM - Thread $ThreadID $Target Phase $Phase -> LIVE HOST HAS GONE MISSING!!\n");
						}
					}# else {
						# It's not local and we're not doing a pingscan. Could just be that the remote host didn't respond
						# to this port range. Give it the benefit of the doubt.
					#}
					$self->CleanUp;
					return 0;
				}

				# Don't do this scan phase again
				$self->SetScanComplete("tcpscan");
				$tcpscanned=1;
			}

		} else {
			$Log->OK ("SDM - Thread $ThreadID $Target Phase $Phase -> Skipped TCP PortScan - already done\n") if ($MainScan->Debug);
		}

		# Clean up and exit if we were paused
		if ($MainScan->WasPaused){
			$self->CleanUp;
			return 0;
		}

		# Store the tcpports file in an array. Don't bannergrab ports in @noBannerGrabPorts.
		my @noBannerGrabPorts=split ",", $MainScan->NoBannerGrabPorts;
		$$self{'openPorts'}=\@openPorts;

		if (!$tcpscanned && -f "${outputDir}/tcpports.txt"){
			for my $_data ($MainScan->ReadFile("${outputDir}/tcpports.txt")){			
				my ($port, $svc) = split "\\s", $_data;
				push @openPorts, $port;
			}
		}

		if ($#openPorts >= 0){

			# ********
			# RPC Info - copy into tcpports.txt
			if ($self->haveTCPPort(111) && !defined($RPCInfo)){
				my $err=$MainScan->System($MainScan->getPath("rpcinfo") . " -p $Target > ${outputDir}/rpcinfo.txt 2>/dev/null");
				if (!$err && -f "${outputDir}/rpcinfo.txt"){
					$RPCInfo=RPCInfo->new("${outputDir}/rpcinfo.txt");
					if ($RPCInfo){
						my @RPCPorts=$RPCInfo->ListTCPPorts;
						if ($#RPCPorts >=0 ){
							for my $_port (@RPCPorts){
								for my $__port (@openPorts){
									next if ($_port == $__port);
									my $_svc=$RPCInfo->TCPProg($_port);
									$MainScan->DelStatKey("${outputDir}/tcpports.txt",$_port);
									$MainScan->SetStatValue("${outputDir}/tcpports.txt",$_port,$_svc);
								}
							}
						}
					}
					$self->SetSingleScanComplete("rpcinfo");
				} else {
					unlink "${outputDir}/rpcinfo.txt";
				}
			}

			# Process RPC info
			if (-f "${outputDir}/rpcinfo.txt" && $RPCInfo){
				push @noBannerGrabPorts, $RPCInfo->ListTCPPorts;
				# If we haven't done it yet, add the RPC ports to openPorts so they can go through
				# the normal service identification process.
				my @RPCPorts=$RPCInfo->ListTCPPorts;
				if ($#RPCPorts >=0 ){
					for my $_port (@RPCPorts){
						for my $__port (@openPorts){
							next if ($_port == $__port);
							push @openPorts, $_port;
						}
					}
				}
			}

			# Get ready for banner grabbing
			mkdir "${outputDir}/banners";

			# ***************
			# TCP Banner Grab
			$Log->Info ("SDM - Thread $ThreadID Identifying services on $Target\n",'LOGONLY') if ($MainScan->Debug);

			sub _noBannerGrab {
				no warnings;
				my $_port=shift();
				for my $_p (@noBannerGrabPorts){
					if ($_port eq $_p){
						return 1;
					}
				}
				return 0;
			}

			my $speedstring="Speeds.$SpeedProfile.sbg." . $MainScan->Speed;
			my $timeout=$Config->GetVal($speedstring);

			for my $line (@openPorts){
				my ($port,$svc)=split " ", $line;
				next if (_noBannerGrab($port));
				if (! -f "${outputDir}/banners/${port}.txt"){
					# Clean up and exit if we were paused
					if ($MainScan->WasPaused){
						$self->CleanUp;
						return 0;
					}
					my $grab=1;

					if (($port == 139) || ($port == 445)){
						$MainScan->System($MainScan->getPath("smbclient") . " -L //$Target/ -U \"\" -N -p $port 2> ${outputDir}/banners/${port}.txt 1>&2");
						if (open(FH,"${outputDir}/banners/${port}.txt")){
							until (eof FH){
								my $line=readline(*FH);
								if ($line =~ /OS=\[[\s\S]+\]\s+Server=\[[\s\S]+\]/i){
									$grab=0;
									last;
								}
							}
							close FH;
						}
					}

					if ($grab){
						my $error=$MainScan->System($MainScan->getPath("sbg") . " -t \"$timeout\" $Target $port > ${outputDir}/banners/${port}.tmp 2>/dev/null");
						if (!$error){
							$MainScan->System("mv ${outputDir}/banners/${port}.tmp ${outputDir}/banners/${port}.txt") if (-f "${outputDir}/banners/${port}.tmp");
						} else {
							unlink "${outputDir}/banners/${port}.tmp";
							$Log->Warn("SDM - Thread $ThreadID Bannergrab - Failed to grab $Target port $port\n",'LOGONLY');
						}
					}
				}
			}

			# Service Identification
			my $confirmed="${outputDir}/confirmedtcpports.txt";
			my $unConfirmed="${outputDir}/unconfirmedtcpports.txt";

			# Get Nmap service ID speed and intensity levels
			my $nmapsVSpeed=$Config->GetVal("Speeds.$SpeedProfile.nmapsv.tcp." . $MainScan->Speed);
			my $nmapsVIntensity=$Config->GetVal("Intensity.$SpeedProfile.nmapsv.tcp." . $MainScan->Intensity);

			# Get amap service ID speed and intensity levels
			my $amapIntensity=$Config->GetVal("Intensity.$SpeedProfile.amap.tcp." . $MainScan->Intensity);
			my $amapRT=$Config->GetVal("Speeds.$SpeedProfile.amap.responsetimeout.tcp." . $MainScan->Speed);
			my $amapCT=$Config->GetVal("Speeds.$SpeedProfile.amap.connecttimeout.tcp." . $MainScan->Speed);
			my $amapRC=$Config->GetVal("Speeds.$SpeedProfile.amap.reconnects.tcp." . $MainScan->Speed);

			my @sigs=$MainScan->ReadFile($Config->GetVal("ResourceDirectory") . "/" . $Config->GetVal("BannerSignatures"));
			for my $portspec (@openPorts){
				my ($port,$junk)=split "\\s", $portspec;
				# Skip this port if we've already classified it
				next if ($MainScan->GetStatKey($confirmed,$port));
				next if ($MainScan->GetStatKey($unConfirmed,$port));

				my $identified=0;	my ($bannerSlice,$service,$method,$nmapPossibly,$nmapPossiblyBS)=("","","","","","");

				# Try RPC Info first
				if ($RPCInfo){
					if ($RPCInfo->HaveTCPPort($port)){
						$identified=1;
						$service=$RPCInfo->TCPProg($port);
						if ($service =~ /^\d+$/){
							$service="RPC-$service";
						}
						$method="RPC Portmapper";
					}
				}

				if (!$identified && (-f "${outputDir}/banners/${port}.txt")){

					# Try clear-text banner analysis next
					my @banner=$MainScan->ReadFile("${outputDir}/banners/${port}.txt");
					for my $sig (@sigs){
						next if (($sig !~ /\S/) || ($sig =~ /^\s/) || ($sig =~ /^\#/));
						chomp $sig;
						my ($Service,$Slice,@Triggers)=split "\@", $sig;

						my $_Triggers=0; my $_Matches=0;
						for my $_trig (@Triggers){
							$_Triggers++;
							for my $line (@banner){
								#print "CHECK $_trig V $line" if ($port == 139);
								next if (!$line || $line !~ /\S/);
								if ($line =~ /$_trig/){
									#print "MATCHED $line\n";
									$_Matches++;
									last;
								}
							}
						}

						if ($_Matches == $_Triggers){
							my $_Line;
							for my $line (@banner){
								#print "Banner:$port:$line";
								if ($line =~ /$Slice/){
									$_Line=$line;
									$_Line =~ s/[\r\n]//g;
									last;
								}
							}
							$identified=1; $service="$Service"; $method="Banner Analysis"; $bannerSlice=$_Line if($_Line);
							#print "Banner IDENTIFIED $service ($Target : $port)\n";
						}	
					}
				}

				if (!$identified && (!_noBannerGrab($port)) && !$MainScan->KidGloves){

					# Clean up and exit if we were paused
					if ($MainScan->WasPaused){
						$self->CleanUp;
						return 0;
					}

					# Now try NMAP service identification if we don't know what it is yet
					mkdir "${outputDir}/raw/nmapsv";
					my $cmd=$MainScan->getPath("nmap") . " -e $Interface -sV -P0 $Target -r -n -T \"$nmapsVSpeed\" --version-intensity \"$nmapsVIntensity\" -p $port -oX ${outputDir}/raw/nmapsv/${port}.xml -oG ${outputDir}/raw/nmapsv/${port}.gnmap> /dev/null";
					#$Log->Info ("SDM - CHILD PID $$ Executing: $cmd\n",'LOGONLY');
					my $error=$MainScan->System("$cmd 2>/dev/null");
					if (!$error){
						# Parse the results
						my $np = JR::Parsers::Nmap->new();
        		if ($MainScan->WasPaused){
        			$self->CleanUp;
	        		return 0;
	    	    }
						$np->parsefile("${outputDir}/raw/nmapsv/${port}.xml");
						my $Host=$np->get_host($Target);
						if ($Host){
							my $PortObj=$Host->tcp_service($port);
							if (open(SVC,">${outputDir}/raw/nmapsv/${port}.txt")){
								print SVC "Name> " . $PortObj->name . "\n" if ($PortObj->name);
								print SVC "Protocol> " . $PortObj->proto . "\n" if ($PortObj->proto);
								print SVC "Confidence> " . $PortObj->confidence . "\n" if ($PortObj->confidence);
								print SVC "Extrainfo> " . $PortObj->extrainfo . "\n" if ($PortObj->extrainfo);
								print SVC "Method> " . $PortObj->method . "\n" if ($PortObj->method);
								print SVC "Product> " . $PortObj->product . "\n" if ($PortObj->product);
								print SVC "RPC number> " . $PortObj->rpcnum . "\n" if ($PortObj->rpcnum);
								print SVC "Version> " . $PortObj->version . "\n" if ($PortObj->version);
								print SVC "Tunnel> " . $PortObj->tunnel . "\n" if ($PortObj->tunnel);
								close SVC;
							}
							if ($PortObj->name){
								if($PortObj->confidence > 4){
									$identified=1;

									# SSL Services - get a bit of clarity - HTTPS in particular - neet 0.4.1
									if ($PortObj->tunnel && (($PortObj->tunnel eq "ssl") || ($PortObj->tunnel eq "tls"))){
										if ($PortObj->name eq "http"){
											$service="https";
										} else {
											$service="ssl"
										}
									} else {
										$service=$PortObj->name;
									}
									if (($PortObj->name eq "http") && ($PortObj->product && ($PortObj->product =~ /Apache SSL-only/))){
										$service="https";
									}

									$method="Nmap sV";
									$bannerSlice .= $PortObj->product if ($PortObj->product);
									$bannerSlice .= " Version " . $PortObj->version if ($PortObj->version);

								} else {
									if ($PortObj->confidence > 1){
										$nmapPossibly=$PortObj->name;
										$nmapPossiblyBS .= "(low confidence: " . $PortObj->confidence . ") " . $PortObj->product if ($PortObj->product);
										$nmapPossiblyBS .= " Version " . $PortObj->version if ($PortObj->version);
									}
								}
							}
						}
					}
				}

				if (!$identified && (!_noBannerGrab($port)) && !$MainScan->KidGloves){
					# Clean up and exit if we were paused
					if ($MainScan->WasPaused){	
						$self->CleanUp	;
						return 0;
					}

					# Now try AMAP service identification if we don't know what it is yet
					mkdir "${outputDir}/raw/amap";
					my $cmd=$MainScan->getPath("amap") . " \"$amapIntensity\" -t \"$amapRT\" -T \"$amapCT\" -C \"$amapRC\" -q -o ${outputDir}/raw/amap/${port}.txt -m $Target $port >/dev/null";

					my $error=$MainScan->System("$cmd  2>/dev/null");
					if (!$error){
						my $AmapOutput=Amap->new("${outputDir}/raw/amap/${port}.txt");
						if ($AmapOutput){
							my $Matches=$AmapOutput->NumberMatches;
							# Need some logic here to sort it out. 
							# In the meantime, I think we'll just take the first match
							if ($Matches && ($AmapOutput->Identification(1) !~ /mysql/i) && ($AmapOutput->Identification(1) !~ /response_of_many_applications/i)){
								$identified=1;
								$service=$AmapOutput->Identification(1);
								$method="Amap";
							}
						}
					}
				}

				if (!$identified && $nmapPossibly){
					# Identify it as nmap's lower-confidence rated services
					$identified=1;
					$service=$nmapPossibly;
					$method="nmap sV";
					$bannerSlice = $nmapPossiblyBS if ($nmapPossiblyBS);
				}

				if ($identified && ($service eq "tcpwrapped")){
					$identified=0;
				}

				# Find out what nmap would have listed it as
				my $nmapService;
				if (!$identified){
					$nmapService=NmapService($outputDir,$port);
				}

				# Commented out for neet 0.4.1 - modified nmap parser instead for better HTTPS finding
				# This is a quick hack to get around listing some HTTPS services on 443
				# in the HTTP.txt file and not in the HTTPS.txt file as they should.
				#if (($service =~ /^http$/) && ($port == 443)){
				#	$service = "https";
				#}

				if (!$identified && $nmapService){
					$service=$nmapService;
				}

				if ($service){
					$service =~ s/\s//g; $service =~ s/[\/\|]/-/g;
					# Use a translated "friendly" name if we have one. See if we have a translation in the
					# servicenames.neet file (in the resources directory)
					my $translated=$MainScan->GetStatValue($ServiceNames,lc($service));

					if ($translated){
						$service = $translated;
					} else {
						$service=Capitalise($service);
					}
				}

				if ($identified){
					# List the service in the confirmed services file	
					if ($bannerSlice){
						$MainScan->SetStatValue("$confirmed",$port,"$service [By $method] $bannerSlice");
					} else {
						$MainScan->SetStatValue("$confirmed",$port,"$service [By $method]");
					}
				} else {
					# List the service in the unconfirmed services file
					if ($service){
						$MainScan->SetStatValue("$unConfirmed",$port,"$service");
					} else {
						$service="Unidentified";
						$MainScan->SetStatKey("$unConfirmed",$port);
					}
				}

				# List the service in the appropriate protocol file.
				my $_outfile="services/" . lc($service) . ".txt";
				my $string="${Target}:${Protocol}/$port";
				$string .= " $bannerSlice" if ($bannerSlice);
				if (!$MainScan->GetStatKey("$_outfile","${Target}:${Protocol}/$port")){
					$MainScan->SetStatKey("$_outfile","$string")
				}

				# Log any issues found
				my ($label,$type,$text)=$MainScan->GetSDMIssue($service,$bannerSlice);
				if ($text){
					$text =~ s/\%HOST\%/$Target/g; $text =~ s/\%PORT\%/$port/g; $text =~ s/\%SERVICE\%/$service/g;  $text =~ s/\%PROTO\%/$Protocol/g;
					my $target="$Target:$port/$Protocol";
					if ($type eq "comp"){
						$MainScan->RecordCompromise($target, $label, $text);
					} elsif ($type eq "vuln"){
						$MainScan->RecordVulnerability($target, $label, $text);
					} else {
						$MainScan->RecordIssue($target, $label, $text);
					}
				}

				# Guess the OS for this service
				if ($service && $bannerSlice){
					my ($type,$family,$fconf,$version,$vconf,$servicepack,$sconf)=$MainScan->OSDetect->BannerToOS($service,$bannerSlice);
					if ($family){
						# Store the results in a hash for guessing progress so far this phase
						$OSPGuess{"$svccount"}{'type'}=$type; $OSPGuess{"$svccount"}{'family'}=$family;
						$OSPGuess{"$svccount"}{'fconf'}=$fconf; $OSPGuess{"$svccount"}{'version'}=$version; $OSPGuess{"$svccount"}{'vconf'}=$vconf;
						$OSPGuess{"$svccount"}{'servicepack'}=$servicepack; $OSPGuess{"$svccount"}{'sconf'}=$sconf;

						# Store the results in a hash for guessing progress for the host so far
						$OSGuess{"$osindex"}{'type'}=$type; $OSGuess{"$osindex"}{'family'}=$family;
						$OSGuess{"$osindex"}{'fconf'}=$fconf; $OSGuess{"$osindex"}{'version'}=$version; $OSGuess{"$osindex"}{'vconf'}=$vconf;
						$OSGuess{"$osindex"}{'servicepack'}=$servicepack; $OSGuess{"$osindex"}{'sconf'}=$sconf;
						$osindex++; $svccount++;
						#print "PORT $port [$service] OS GUESS: ($type) $family ($fconf) ";
						#print "$version ($vconf) " if ($version);
						#print "$servicepack ($sconf)" if ($servicepack);
						#print " [ As index $osindex ]\n";
					}
				}
			} # End of port iteration
		} # End of 'if we have open ports' section

		if ($MainScan->WasPaused){
			$self->CleanUp;
			return 0;
		}

		# Clear the OS guess stores for a new calculation
		($type,$family,$fconf,$version,$vconf,$servicepack,$sconf)=("","","","","","","");

		if ("$Phase" ne ($MainScan->Phases - 1)){
			# Not the last phase: write the OSGuess hash to disk
			Storable::store(\%OSGuess, "$OSGuessFile");

			# Now calculate the likely OS version from the services seen so far
			my $c=0;
			for (my $i=0; $i<$svccount; $i++){
				# The family first
				next if (!$OSPGuess{"$i"}{'fconf'});
				if ($OSPGuess{"$i"}{'fconf'} > $c){
					$family=$OSPGuess{"$i"}{'family'};
					$fconf=$OSPGuess{"$i"}{'fconf'};
					$type=$OSPGuess{"$i"}{'type'};
					$c=$fconf;
				}	
			}

			# Version next
			if ($family){
				$c=0;
				for (my $i=0; $i<$svccount; $i++){
					next if (!$OSPGuess{"$i"}{'family'} || !$OSPGuess{"$i"}{'vconf'} || ($OSPGuess{"$i"}{'family'} ne "$family"));
					if ($OSPGuess{"$i"}{'vconf'} > $c){
						$version=$OSPGuess{"$i"}{'version'};
						$vconf=$OSPGuess{"$i"}{'vconf'};
						$c=$vconf;
					}	
				}
			}

			# Service Pack next
			if ($version){
				$c=0;
				for (my $i=0; $i<$svccount; $i++){
					next if (!$OSPGuess{"$i"}{'sconf'} || !$OSPGuess{"$i"}{'family'} || !$OSPGuess{"$i"}{'version'} || ($OSPGuess{"$i"}{'version'} ne "$version") || ($OSPGuess{"$i"}{'family'} ne "$family"));
					if ($OSPGuess{"$i"}{'sconf'} > $c){
						$servicepack=$OSPGuess{"$i"}{'servicepack'};
						$vconf=$OSPGuess{"$i"}{'sconf'};
						$c=$vconf;
					}	
				}
			}

			if ($family){
				my $OS="$family";
				$OS .= " $version" if ($version);
				$OS .= " $servicepack" if ($servicepack);
				#print "OS GUESS Phase $Phase: ($type) $OS\n";

				if (!$MainScan->GetStatKey("${outputDir}/hostInfo.txt","OSType")){
					$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OSType","$type");
				}
				if (!$MainScan->GetStatKey("${outputDir}/hostInfo.txt","OSFamily")){
					$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OSFamily","$family");
					$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OS","$OS");
					$MainScan->SetStatValue("${type}.txt",$Target,"$OS");
  				$Log->Info ("SDM - Thread $ThreadID Initial OS Guess: $OS for $Target \n");
				}
				if ($version && !$MainScan->GetStatKey("${outputDir}/hostInfo.txt","OSVersion")){
					$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OSVersion","$version");
					$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OS","$OS");
					$MainScan->SetStatValue("${type}.txt",$Target,"$OS");
					# See if we can determine the architecture
					if (($version =~ /2000/) || ($version =~ /NT/)){
						$MainScan->SetStatValue("${outputDir}/hostInfo.txt","Architecture","32-bit");
					} elsif ($version =~ /XP/) {
						if ($version =~ /x64/){
							$MainScan->SetStatValue("${outputDir}/hostInfo.txt","Architecture","64-bit");
						} else {
							$MainScan->SetStatValue("${outputDir}/hostInfo.txt","Architecture","32-bit");
						}
					}
				}
				if ($servicepack && !$MainScan->GetStatKey("${outputDir}/hostInfo.txt","OS_ServicePack")){
					$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OS_ServicePack","$servicepack");
					$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OS","$OS");
					$MainScan->SetStatValue("${type}.txt",$Target,"$OS");
				}

				for my $excludedOS ($MainScan->ExcludedOS) {
					next if (!$excludedOS);
					if (($OS =~ /$excludedOS/) || ($type =~ /$excludedOS/)){
						# Cancel the host as it this OS is a forbidden fruit
						my $FH;
						if (open($FH,">${outputDir}/.cancelled")){
							close $FH;
							$Log->Info ("SDM - Thread $ThreadID Cancelled $Target (OS type matched \"$exludedOS)\"\n",'LOGONLY');
						}
						last;
					}
				}
			}

		} else {
			# This *IS* the last phase. Do the final OS guess.

			($type,$family,$fconf,$version,$vconf,$servicepack,$sconf)=$MainScan->OSDetect->HashToOS(\%OSGuess);

			if ($family){
				my $OS="$family";
				$OS .= " $version" if ($version);
				$OS .= " $servicepack" if ($servicepack);
				$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OSType","$type");
				$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OSFamily","$family");
				$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OSVersion","$version") if ($version);
				$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OS_ServicePack","$servicepack") if ($servicepack);
				$MainScan->SetStatValue("${outputDir}/hostInfo.txt","OS","$OS");
				$MainScan->SetStatValue("${type}.txt",$Target,"$OS");
				$Log->Info ("SDM - Thread $ThreadID FINAL OS Guess: $OS for $Target \n");

				for my $excludedOS ($MainScan->ExcludedOS) {
					next if (!$excludedOS);
					if (($OS =~ /$excludedOS/) || ($type =~ /$excludedOS/)){
						# Cancel the host as it this OS is a forbidden fruit
						my $FH;
						if (open($FH,">${outputDir}/.cancelled")){
							close $FH;
							$Log->Info ("SDM - Thread $ThreadID Cancelled $Target (OS type matched \"$exludedOS)\"\n",'LOGONLY');
						}
						last;
					}
				}
			}
		}

    # **********************************************************************************
    # **********************************************************************************

	} elsif ($Protocol eq "udp") {
		my $RPCInfo=undef;
		$#openUdpPorts=-1; $#filteredUdpPorts=-1;

		# *************
		# UDP Port Scan
		if (!$self->IsScanComplete("udpscan")){

			# Construct the command line. Don't use host discovery, as the TCP scan should have done that. Use -P0.
			$_UDPScan=$MainScan->getPath("nmap") . " -e $Interface -sU $Target -n -T \"" . $Config->GetVal("Speeds.$SpeedProfile.nmap.udp." . $MainScan->Speed) . "\" -P0";

			# If we have discovered ports by RPC Info, don't bother port scanning them
			if (-f "${outputDir}/rpcinfo.txt"){
				$RPCInfo=RPCInfo->new("${outputDir}/rpcinfo.txt");
				my $PortSpec=PortRange->new($Ports);
				if ($RPCInfo){
					for my $rpcport ($RPCInfo->ListUDPPorts){
						$PortSpec->Exclude($rpcport);
					}
				}
				$Ports=$PortSpec->RangeSpec;
			}

			my $UDPcommand=$_UDPScan . " -p $Ports -oX $outputXML -oG $outputGrep > $outputTXT";

			# Now run the command using the system() wrapper in MainScan. It is essential to
			# store the return code in the variable "$error". $error should ALWAYS be 0 if
	    # the scan completed OK and a positive integer otherwise.
			$error=$MainScan->System("$UDPcommand 2>/dev/null");

			if (!$error){
				# Parse the results
				my $np = JR::Parsers::Nmap->new();
		    		if ($MainScan->WasPaused){
    					$self->CleanUp;
		    			return 0;
				}
				$np->parsefile("$outputXML");
				my $host=$np->get_host($Target);
				if ($host){
					my $closedPorts=0;

					for my $_port ($host->udp_ports('closed')){
						$closedPorts=1; last;	
					}

					$host->strictUDPOpens();

					for my $_port ($host->udp_ports('open')){
						push @openUdpPorts, $_port;
					}
					for my $_port ($host->udp_ports('filtered')){
						push @filteredUdpPorts, $_port;
					}

					# List the open ports in udpports.txt
					if ($#openUdpPorts >=0 ){
						if (open(PF,">>${outputDir}/udpports.txt")){
							for my $_port (@openUdpPorts){
								my $svc=$host->udp_service($_port);
								my $_name=$svc->name;
								print PF "$_port ";
								print PF "$_name" if ($_name);
								print PF "\n";
							}
							close PF;
						}
					}
					# List the open ports in filteredudpports.txt
					if ($#filteredUdpPorts >=0 ){
						if (open(PF,">>${outputDir}/filteredudpports.txt")){
							for my $_port (@filteredUdpPorts){
								my $svc=$host->udp_service($_port);
								my $_name=$svc->name;
								print PF "$_port ";
								print PF "$_name" if ($_name);
								print PF "\n";
							}
							close PF;
						}
					}
					# Don't do this scan phase again
					$self->SetScanComplete("udpscan");
					$udpscanned=1;
				} # got a host object
			} # No scanning error
		} else {
			$Log->OK ("SDM - Thread $ThreadID $Target Phase $Phase -> Skipped UDP PortScan - already done\n") if ($MainScan->Debug);
		} # UDP scan complete

		if (!$udpscanned && -f "${outputDir}/udpports.txt"){
			for my $_data ($MainScan->ReadFile("${outputDir}/udpports.txt")){			
				my ($port, $svc) = split "\\s", $_data;
				push @openUdpPorts, $port;
			}
		}
		if (!$udpscanned && -f "${outputDir}/filteredudpports.txt"){
			for my $_data ($MainScan->ReadFile("${outputDir}/filteredudpports.txt")){			
				my ($port, $svc) = split "\\s", $_data;
				push @filteredUdpPorts, $port;
			}
		}

		# Process RPC info
		if (-f "${outputDir}/rpcinfo.txt" && $RPCInfo){
			# If we haven't done it yet, add the RPC ports to openUdpPorts so they can go through
			# the normal service identification process.
			my @RPCPorts=$RPCInfo->ListUDPPorts;
			if ($#RPCPorts >=0 ){
				for my $_port (@RPCPorts){
					my $addit=1;
					for my $__port (@openUdpPorts){
						if ($_port == $__port){
							$addit=0;
							last;
						}
					}
					if ($addit){
						my $_svc=$RPCInfo->UDPProg($_port);
						$MainScan->DelStatKey("${outputDir}/udpports.txt",$_port);
						$MainScan->SetStatValue("${outputDir}/udpports.txt",$_port,$_svc);
						push @openUdpPorts, $_port;
					}
				}
			}
		}
	
		if ($#openUdpPorts >= 0){

			# Service Identification
			my $confirmed="${outputDir}/confirmedudpports.txt";
			my $unConfirmed="${outputDir}/unconfirmedudpports.txt";

			# Get Nmap service ID speed and intensity levels
			my $nmapsVSpeed=$Config->GetVal("Speeds.$SpeedProfile.nmapsv.udp." . $MainScan->Speed);
			my $nmapsVIntensity=$Config->GetVal("Intensity.$SpeedProfile.nmapsv.udp." . $MainScan->Intensity);

			for my $line (@openUdpPorts){
				my ($port,$svc)=split " ", $line;
				my $identified=0;
				my ($service,$method,$bannerSlice)=("","","");

				# Try RPC Info first
				if ($RPCInfo){
					if ($RPCInfo->HaveUDPPort($port)){
						$identified=1;
						$service=$RPCInfo->UDPProg($port);
						if ($service =~ /^\d+$/){
							$service="RPC-$service";
						}
						$method="RPC Portmapper";	
					}
				}
		
				if (!$identified && !$MainScan->KidGloves){

					# Clean up and exit if we were paused
					if ($MainScan->WasPaused){
						$self->CleanUp;
						return 0;
					}

					# Now try NMAP service identification if we don't know what it is yet
					mkdir "${outputDir}/raw/nmapsv";
					my $cmd=$MainScan->getPath("nmap") . " -e $Interface -sV -sU -P0 $Target -r -n -T \"$nmapsVSpeed\" --version-intensity \"$nmapsVIntensity\" -p $port -oX ${outputDir}/raw/nmapsv/udp-${port}.xml -oG ${outputDir}/raw/nmapsv/udp-${port}.gnmap > /dev/null";
					#$Log->Info ("SDM - CHILD PID $$ Executing: $cmd\n",'LOGONLY');
					my $error=$MainScan->System("$cmd 2>/dev/null");
					if (!$error){
						# Parse the results
					  my $np = JR::Parsers::Nmap->new();
        		if ($MainScan->WasPaused){
        			$self->CleanUp;
	        		return 0;
		        }
						$np->parsefile("${outputDir}/raw/nmapsv/udp-${port}.xml");
						my $Host=$np->get_host($Target);
						if ($Host){
							my $PortObj=$Host->udp_service($port);
							if (open(SVC,">${outputDir}/raw/nmapsv/udp-${port}.txt")){
								print SVC "Name> " . $PortObj->name . "\n" if ($PortObj->name);
								print SVC "Protocol> " . $PortObj->proto . "\n" if ($PortObj->proto);
								print SVC "Confidence> " . $PortObj->confidence . "\n" if ($PortObj->confidence);
								print SVC "Extrainfo> " . $PortObj->extrainfo . "\n" if ($PortObj->extrainfo);
								print SVC "Method> " . $PortObj->method . "\n" if ($PortObj->method);
								print SVC "Product> " . $PortObj->product . "\n" if ($PortObj->product);
								print SVC "RPC number> " . $PortObj->rpcnum . "\n" if ($PortObj->rpcnum);
								print SVC "Version> " . $PortObj->version . "\n" if ($PortObj->version);
								close SVC;
							}
							if ($PortObj->name){
								if($PortObj->confidence > 2){
									$identified=1;
									$service=$PortObj->name;
									$method="Nmap sV";
									$bannerSlice = $PortObj->product if ($PortObj->product);
									$bannerSlice .= " Version " . $PortObj->version if ($PortObj->version);
								}
							}
						}
					}
				}

				# Find out what nmap would have listed it as
				my $nmapService;
				if (!$identified){
					$nmapService=NmapService($outputDir,$port);
				}

				if (!$identified && $nmapService){
					$service=$nmapService;
				}

				if ($service){
					$service =~ s/\s//g; $service =~ s/[\/\|]/-/g;
					# Use a translated "friendly" name if we have one. See if we have a translation in the
					# servicenames.neet file (in the resources directory)
					my $translated=$MainScan->GetStatValue($ServiceNames,"$service");
					if ($translated){
						$service = $translated;
					} else {
						$service=Capitalise($service);
					}
				}
	
				if ($identified){
					# List the service in the confirmed services file	
					if ($bannerSlice){
						$MainScan->SetStatValue("$confirmed",$port,"$service [By $method] $bannerSlice");
					} else {
						$MainScan->SetStatValue("$confirmed",$port,"$service [By $method]");
					}
				} else {
					# List the service in the unconfirmed services file	
					if ($service)	{
						$MainScan->SetStatValue("$unConfirmed",$port,"$service");
					} else {	
						$service="Unidentified";
						$MainScan->SetStatKey("$unConfirmed",$port);
					}
				}

				# List the service in the appropriate protocol file.
				my $_outfile="services/" . lc($service) . ".txt";
				my $string="${Target}:${Protocol}/$port";
				$string .= " $bannerSlice" if ($bannerSlice);
				if (!$MainScan->GetStatKey("$_outfile","${Target}:${Protocol}/$port")){
					$MainScan->SetStatKey("$_outfile","$string")
				}

				# Log any issues found
				my ($label,$type,$text)=$MainScan->GetSDMIssue($service,$bannerSlice);
				if ($text){
					$text =~ s/\%HOST\%/$Target/g; $text =~ s/\%PORT\%/$port/g; $text =~ s/\%SERVICE\%/$service/g;  $text =~ s/\%PROTO\%/$Protocol/g;
					my $target="$Target:$port/$Protocol";
					if ($type eq "comp"){
						$MainScan->RecordCompromise($target, $label, $text);
					} elsif ($type eq "vuln"){
						$MainScan->RecordVulnerability($target, $label, $text);
					} else {
						$MainScan->RecordIssue($target, $label, $text);
					}
				}

			} # for each port

		} # OpenUdpPorts > 0	

	} # Proto eq udp

	$Log->Info("SDM - Thread $ThreadID FINISHED $Target Phase $Phase Proto $Protocol range $Ports\n") if ($MainScan->Debug);

}

sub ReadFile {
	use Fcntl ':flock';
	# Reads $file into an array
	my $file=shift();
	if (-f $file && open(F,$file)){
		flock(F,LOCK_EX);
		my @_file=<F>;
		flock(F,LOCK_UN);
		close F;
		return @_file;
	}
	return undef;
}

sub NmapService {
	my $outputDir=shift();
	my $port=shift();
	if ($port && ($port =~ /^\d+/) && (-f "${outputDir}/tcpports.txt")){
		#my @_file=$MainScan->ReadFile("${outputDir}/tcpports.txt");
		my @_file=ReadFile("${outputDir}/tcpports.txt");
		for my $line (@_file){
			my ($_port,$svc)=split " ", $line;
			return $svc if ($svc && ($port == $_port));
		}
	}
	return 0;
}

sub Capitalise {
	my $service=shift();
	if (!$service){
		return undef;
	}
	my $capitalised;
	if ($service =~ /^http$|^https$|^ftp$|^ntp$|^smb|^smtp$|^snmp$|^ssh$|^ssl$|^ldap$|^nntp$|^pop\d{0,}$|^vnc$|^msrpc$|^irc$|^wins$|^dhcp|^tftp$|^nfs$|^tacacs$|^xdmcp$|^bgp$|^rtsp$|^ipp$|^imap$|^uucp$/i){
		$capitalised=uc($service);
	} else {
		$capitalised=ucfirst(lc($service));
	}
	return $capitalised;
}

sub haveTCPPort {
	my $self=shift();
	my $_port=shift();
	for my $svc (@{$$self{'openPorts'}}){
		my ($_p,$junk)=split " ", $svc;
		if ($_port eq $_p){
			return 1;
		}
	}
	return 0;
}

sub CleanUp {
	my $self=shift();
	my $Target=$$self{'Target'};
	# Doesn't need to do anything any more
	return 0;
}

sub SetScanComplete {
	my $self=shift();
	my $_name=shift();
	my $MainScan=$$self{'MainScan'};
	my $_phase=$$self{'Phase'};
	my $_scanName="SDM_${_phase}_$_name";
	$MainScan->SetStatKey($$self{'StatusFile'},$_scanName);
	return 1;
}

sub SetScanInComplete {
	my $self=shift();
	my $_name=shift();
	my $MainScan=$$self{'MainScan'};
	my $_phase=$$self{'Phase'};
	my $_scanName="SDM_${_phase}_$_name";
	if ($MainScan->DelStatKey($$self{'StatusFile'},$_scanName)){
		return 1;
	} else {
		return 0;
	}
}

sub IsScanComplete {
	my $self=shift();
	my $_name=shift();
	my $MainScan=$$self{'MainScan'};
	my $_phase=$$self{'Phase'};
	my $_scanName="SDM_${_phase}_$_name";
	return $MainScan->GetStatKey($$self{'StatusFile'},$_scanName);
}


sub SetSingleScanComplete {
	# SingleScans differ from Scans in that they can only be run once per host, whereas
	# Scans can be run in every phase.
	my $self=shift();
	my $_name=shift();
	my $MainScan=$$self{'MainScan'};
	my $_scanName="SDM_$_name";
	$MainScan->SetStatKey($$self{'StatusFile'},$_scanName);
	return 1;
}

sub SetSingleScanInComplete {
	my $self=shift();
	my $_name=shift();
	my $MainScan=$$self{'MainScan'};
	my $_scanName="SDM_$_name";
	if ($MainScan->DelStatKey($$self{'StatusFile'},$_scanName)){
		return 1;
	} else {
		return 0;
	}
}

sub IsSingleScanComplete {
	my $self=shift();
	my $_name=shift();
	my $MainScan=$$self{'MainScan'};
	my $_scanName="SDM_$_name";
	return $MainScan->GetStatKey($$self{'StatusFile'},$_scanName);
}

1;
