#! /usr/bin/perl
# add version here

  use strict;
  use warnings;
  use Data::Dumper;
  use Net::SNMP;
  use DBI;
  use Getopt::Std;
  use NetAddr::IP; 
  use vars qw(@forwardheader @revheader @exlzone $workdir $nedidb $nediuser $nedipwd $ipamdb $ipamuser $ipampwd $community $section);
  require "pia.conf";
  
  my $OID_sysUpTime = '1.3.6.1.2.1.1.3.0';
  my $OID_sysContact = '1.3.6.1.2.1.1.4.0';
  my $OID_sysLocation = '1.3.6.1.2.1.1.6.0';
  #--------
  my $HOSTNAME_OID=".1.3.6.1.2.1.1.5.0";
  my $IFDESCR_OID=".1.3.6.1.2.1.2.2.1.2";
  my $ifDescrOid="1.3.6.1.2.1.2.2.1.2";
  my $ifAdminStatus=".1.3.6.1.2.1.2.2.1.7";
  # Values: 1 : up
  #         2 : down
  #         3 : testing
  
  my $ipAdEntNetMask="1.3.6.1.2.1.4.20.1.3";

  my $ADDRESSES_OID=".1.3.6.1.2.1.4.20.1.2";
  my $VRF_INT_STAT="1.3.6.1.3.118.1.2.1.1.6";
  my $mplsVpnVrfTableCisco="1.3.6.1.3.118.1.2.1.1.6";
  #my $VpnServiceIdTableHuawei="1.3.6.1.4.1.2011.5.25.177.2.2.1";
  my $VpnServiceIdTableHuawei="1.3.6.1.2.1.10.166.11.1.2.1.1.2";
 
  my $snmpver = 'snmpv2c';
  my %opt=();
  my $verbose = 1;
  # Vpn instance name; default - '' (GRT); use '*' placeholder for all instances;
  my $vpn = '';
  my $inputfile="";

  #  Global val = 
  my $defpermissions = '{"3":"1","2":"2"}';

  # The nwt mask to expand all host addresses (/32) to
  my $smlln = 24;
  # IP version; default INET4
  my $ipver = 4;

  my ($ipstart, $ipstop);
  $ipstart = $ipstop = "127.0.0.1";
  getopts('H:i:s:l:m:r:f:vhd',\%opt) or HELP();

  if ($opt{'H'}) {
    # IP address range A:B
    # from A to B
    ($ipstart, $ipstop) = split /:/,$opt{'H'};
    $ipstart = "127.0.0.1" if (!$ipstart);
    $ipstop = $ipstart if (!$ipstop);
    if (!$opt{'f'}) {
      if ((!isip($ipstart)) or (!isip($ipstop))) {
    	print "Wrong IP range $opt{'H'}!\n";
        die;
      }
      vout (sprintf "Host list: Nedi DB, starts from %s, to %s\n", $ipstart,$ipstop);
    }
  }
  if ($opt{'d'}) {
    #dry run
    vout ("==Dry Run!==");
  }
  if ($opt{'v'}) {
    # verbose
    $verbose = 1;
  }
  if ($opt{'r'}) {
    if ((isip((split/\//,$opt{'r'})[0])) and ((int((split/\//,$opt{'r'})[1]))<32) and ((int((split/\//,$opt{'r'})[1]))>1)) {
    #if ((isip((split/\//,$opt{'r'})[0])) and ((int(split/\//,$opt{'r'})[1])<32 )) {
      vout (sprintf "Find subnets that fall into range %s",$opt{'r'});
    } else {
      vout (sprintf "Error in network definition %s",$opt{'r'});
      exit 0; 
    }
  }

  if ($opt{'i'}) {
    #vpn **i**nstances
    $vpn = $opt{'i'};   
  }
  if ($opt{'m'}) {
    #**m**odify/move ip addresses from given vrf ('i' option) into this instance
  }
  if ($opt{'s'}) {
    # IPAM **s**ection
    $section = $opt{'s'};   
  }
  if ($opt{'f'}) {
    # read device list from a **f**ile instead of from the NEDI DB
    $inputfile = $opt{'f'};   
    vout (sprintf "Host list: input file \'%s\'",$opt{'f'});
  }
  if ($opt{'h'}) {
    &HELP;
    die;
  }

  #--------------------------------------------------
  #   START 
  
  my %hosts;
  my ($dbh, $sth, $sqlstr);
  if ($inputfile) { 
    die "Host file \'$inputfile\' doesn't exist! $!" unless (-e $inputfile);
    %hosts = mkHostList($inputfile);  
  } else {
    $sqlstr = "SELECT device, devip, INET_NTOA(devip),devos from devices  where devip between INET_ATON('".$ipstart."') and INET_ATON('".$ipstop."') order by devip";
    $dbh = DBI->connect("DBI:mysql:$nedidb", $nediuser, $nedipwd,
                          { RaiseError => 1 }) or die;
    $sth = $dbh->prepare($sqlstr);
    $sth->execute();
    print "The next hosts are going to be treated: \n" if $verbose;
    while (my ($name, $ip, $mip,$devos) =
        $sth->fetchrow_array())  # repeat until no more entries are left
    {
      print "\t$name => $mip\n" if $verbose;
      $hosts{$mip}=$devos;
    }
    $sth->finish();
    $dbh->disconnect();
    undef $sth; undef $dbh;
    print "--------------------------------------------------------------------------\n" if $verbose;
  }

  # Connect to the IPAM DB. Keep DB handlers opened
  $dbh = DBI->connect("DBI:mysql:$ipamdb", $ipamuser, $ipampwd,
                      { RaiseError => 1 });
  # Check section first
  $sqlstr = "SELECT DISTINCT(id),name FROM sections WHERE BINARY name=?;";
  $sth = $dbh->prepare($sqlstr);
  $sth->execute($section);
  my ($dsecid, $dsecname) = $sth->fetchrow_array();
  if (!$dsecid) {
    # No given section at all - exit!
    vout(sprintf "\t\tCouldn't find the given section '%s'! Die", $section);  
    exit 0; 
  }

  # Select vpn instances from DB
  #There is always a one vrf in the hash reflecting GRT
  my %dbvrf;
  $dbvrf{''}=0;
 
  $sqlstr = "SELECT vrfId,name FROM vrf;";
  $sth = $dbh->prepare($sqlstr);
  $sth->execute();
  while (my ($vid, $vname) =
    $sth->fetchrow_array())  # repeat until no more entries are left
  {
    $dbvrf{$vname}=$vid;
  }
  print "---------------------------------------\n";
  print "DBVRF: \n";
  print Dumper %dbvrf;
  print "---------------------------------------\n";
 
  my $tvpn; # VPN instance for host/snmp fetched data
  my $dvpn; # VPN instance for DB fetched data
  #if (($opt{'m'}) and ($opt{'i'})) {
  if ($opt{'m'}) {
    if (!$dbvrf{$opt{'m'}}) {      
      vout(sprintf "Cann't find the given instance \'%s\' to migrate to. Exit", $opt{'m'});
      exit 0;
    }
    $dvpn = $opt{'m'};
  } else {
    $dvpn = $vpn;
  }
  if ((!$dbvrf{$vpn}) and ($vpn ne '') and ($vpn ne '*')) {      
      vout(sprintf "Cann't find the given instance \'%s\' within the DB. Exit", $vpn);
      exit 0;
  }

  # SNMP device poll
  # Create a session for each host and queue a non-blocking get-request.
  my (%table, %table2);

#=begin text

=pod

%table format is:
%table = ( 
      * $host => { //'10.22.50.25 '
      	'vrfs' => [ $vrf1, $vrf2, ..., $vrfx ], //'red', 'blue', 'exta'
      	'hostname' => $hostname, //'zs01-kyi01-lab.dn.ukr'
      	'indexes' => {
                       ** $idx => { //'396'
      			'ip'      => $IPv4_address, //'10.2.2.10'
      	     		'descr'   => $interface_name, //'GigabitEthernet9/27'
      			'vrf'     => $vrf_name,
      			'admstst' => $if_admin_state // 2 (1:Up, 2:Down, 3:Testing)
      		     }
              }
      }
) 

%table2 format is:
%table2 = (
       * $host => { //'10.22.50.25 '
       		$ip => { //'10.2.2.10'
       	     		** 'idx' => $snmp_interface_index, // 12
       			'mask' => $if_octet_mask, //'255.255.255.252'
       			'id'   => $ordered_number //5
		}	
	}
)
 ,where 
    $table{$host} == $table2{$host},
    $table{$host}{'indexes'}{$idx} == $table2{$host}{$ip}{'idx'},
    $table{$host}{'indexes'}{'ip'} == $table2{$host}{$ip}
 
=cut

#=end text
  
  #for my $hc (0 .. $#hosts) {
  foreach my $host (sort keys %hosts) {
    printf "Processing host '%s' {%s}...\n", $host,$hosts{$host} if $verbose;
    my ($session, $error) = Net::SNMP->session(
    	-hostname    => $host,
        -community   => $community,
        -nonblocking => 1,
	-translate   => [-octetstring => 0],
	-version     => 'snmpv2c',
    );

    if (!defined $session) {
    	printf "ERROR: Failed to create session for host '%s': %s.\n",
          $host, $error if $verbose;
        next;
    }
    my $result = $session->get_request(
    	-varbindlist => [ $HOSTNAME_OID ],
        -callback    => [ \&get_hostname, $host, \%table ],
    );

    if (!defined $result) {
      printf "ERROR in get request: %s\n", $session->error() if $verbose;
      $session->close();
    	next;
    }
    undef $result;

    if ($hosts{$host} =~ /^HuaweiVRP$/) {
      $result = $session->get_table(
        -baseoid       => $VpnServiceIdTableHuawei,
        -callback       => [ \&get_vrf_int, $VpnServiceIdTableHuawei, \%table ],
      );
    } elsif ($hosts{$host} =~ /^IOS/) {
      $result = $session->get_table(
        -baseoid       => $mplsVpnVrfTableCisco,
        -callback       => [ \&get_vrf_int, $mplsVpnVrfTableCisco, \%table ],
      );
    }
    if (!defined $result) {
        printf "ERROR: Failed to get vrf table request for host '%s': %s.\n",
                $session->hostname(), $session->error() if $verbose;
    	$session->close();
    	next;
    };
   
    undef $result;
    $result = $session->get_table(
        -baseoid       => $ifDescrOid,
        -callback       => [ \&get_interface_description, \%table, \%table2 ],
    );

    if (!defined $result) {
      printf "ERROR: Failed to get interface description table request for host '%s': %s.\n",
            $session->hostname(), $session->error() if $verbose;
      $session->close();
      next;
    }; 

    undef $result;
    $result = $session->get_table(
        -baseoid       => $ifAdminStatus,
        -callback       => [ \&get_interface_admin_status, \%table ],
    );

    if (!defined $result) {
      printf "ERROR: Failed to get interface admin status table request for host '%s': %s.\n",
            $session->hostname(), $session->error() if $verbose;
      $session->close();
      next;
    };
	
    undef $result;
    $result = $session->get_table(
        -baseoid       => $ipAdEntNetMask,
        -callback       => [ \&get_interface_ipmask, \%table2 ],
    );

    if (!defined $result) {
      printf "ERROR: Failed to get interface ip mask table request for host '%s': %s.\n",
            $session->hostname(), $session->error() if $verbose;
      $session->close();
      next;
    };
	
    # Now initiate the SNMP message exchange.
    snmp_dispatcher();
  }

  print Dumper %table;
  print "-----------------\n";
  print Dumper %table2;
  print "-----------------\n";
  
  my %tnet;
  my %dbnet;

=pod

:TNET: 

%tnet = ( 
	$vpn => { //'blue'
		$ip_prefix => { // '192.168.102.0/24'
                        'mask' => $prefix_mask, //24
                	'inetn' => $INET_ATON, //'3232261632',
                        'descr' => $description, // 'Aggr Host (/32) net'
                        'iplist' => {
				$ip_address1 => $ip_description1, // '192.168.102.2' => 'zs01-kyi01-lab Loopback65202',
				...,
				$ip_addressX => $ip_descriptionX
                        }
                }
        }
)

=cut

  for my $key ( sort keys %table2 ) { 
    for my $key2 (sort keys %{$table2{$key}}) {
      if ($table{$key}{'indexes'}{$table2{$key}{$key2}{'idx'}}{'admstat'} == 1) {
        my $xvrf = '';
        $xvrf = $table{$key}{'indexes'}{$table2{$key}{$key2}{'idx'}}{'vrf'} 
               if ($table{$key}{'indexes'}{$table2{$key}{$key2}{'idx'}}{'vrf'});
        my $ip = NetAddr::IP->new($key2,$table2{$key}{$key2}{'mask'});
        my $prfx = $ip->network();
        my $ipnet = NetAddr::IP->new($prfx);
        my ($ipaddr, $ipmask) = split /\//, $ip; 
        my $descr = sprintf "%s", $prfx;
        if ($ipmask == 32) {
          $descr = "Aggr Host (/32) net";
          $ipmask = $smlln;
          $ip = NetAddr::IP->new($key2,$smlln); 
          $prfx = $ip->network();
          $ipnet = NetAddr::IP->new($prfx);
        } 
        $tnet{$xvrf}{$prfx}{'mask'} = $ipmask;
        $tnet{$xvrf}{$prfx}{'inetn'} = $ipnet->numeric();
        $tnet{$xvrf}{$prfx}{'descr'} = $descr;
        # Trim domainname part of the hostname if any
        (my $hn = $table{$key}{'hostname'}) =~ s/^(.*?)\..*$/$1/; 
        #$tnet{$xvrf}{$prfx}{'iplist'}{$key2} = $table{$key}{'hostname'} . " " . $table{$key}{'indexes'}{$table2{$key}{$key2}{'idx'}}{'descr'};
        $tnet{$xvrf}{$prfx}{'iplist'}{$key2} = $hn . " " . $table{$key}{'indexes'}{$table2{$key}{$key2}{'idx'}}{'descr'};
      }
    }
  }
  print "-----------------\n::";
  print "TNET: \n";
  print Dumper %tnet;
  print "-----------------\n::";

  if ($dvpn eq '*') { 
    if ($ipver == 4) {
      $sqlstr = "SELECT s.id,s.subnet,INET_NTOA(s.subnet) AS ipv4addr,s.mask,s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev,v.name FROM subnets s, vrf v WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) < '4294967295' AND v.vrfid=s.vrfid  UNION  SELECT s.id,s.subnet,INET_NTOA(s.subnet) AS ipv4addr,s.mask,s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev, '' FROM subnets s WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) < '4294967295' AND s.vrfid=0 ORDER BY sectionId,subnet;";
    } else {
      # IPv6
      $sqlstr = "SELECT s.id,s.subnet,CAST(`subnet` AS UNSIGNED) AS ipv6addr,s.mask,s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev,v.name FROM subnets s, vrf v WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) > '4294967295' AND v.vrfid=s.vrfid  UNION  SELECT s.id,s.subnet,CAST(`subnet` AS UNSIGNED) AS ipv6addr,s.mask,s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev,'' FROM subnets s WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) > '4294967295' AND s.vrfid=0 ORDER BY sectionId,subnet;";
    }
  } elsif ($dvpn eq '') {
    # No vrf - GRT (default)
    if ($ipver == 4) {
      $sqlstr = sprintf("SELECT s.id,s.subnet,INET_NTOA(s.subnet) AS ipv4addr,s.mask,s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev, '' FROM subnets s WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) < '4294967295' AND s.vrfid=0 AND s.sectionId=%s ORDER BY sectionId,subnet;",$dsecid);
    } else {
      # IPv6
      $sqlstr = "SELECT s.id,s.subnet,CAST(`subnet` AS UNSIGNED) AS ipv6addr,s.mask,s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev,'' FROM subnets s WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) > '4294967295' AND s.vrfid=0 ORDER BY sectionId,subnet;";
    }
  }
  else {
    if ($ipver == 4) {
      $sqlstr = sprintf "SELECT s.id,s.subnet,INET_NTOA(s.subnet) AS ipv4addr,s.mask,s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev,v.name FROM subnets s, vrf v WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) < '4294967295' AND v.vrfid=s.vrfid AND v.name='%s' AND s.sectionId=%s;", $dvpn, $dsecid;
    } else {
      $sqlstr = sprintf "SELECT s.id,s.subnet,CAST(`subnet` AS UNSIGNED) AS ipv6addr,s.mask,s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev,v.name FROM subnets s, vrf v WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) > '4294967295' AND v.vrfid=s.vrfid AND v.name='%s' AND s.sectionId=%s;", $dvpn, $dsecid; 
    }
  }

  $sth = $dbh->prepare($sqlstr);
  $sth->execute();
  while (my ($sid, $subnet, $subnetn,$smask,$ssectionid,$svrfid,$smastersubnetid,$spermissions,$saggdev,$svrfname) =
    $sth->fetchrow_array())  # repeat until no more entries are left
  {
    my ($spref, $apref);
 #   printf "Subnet %s (%s)/%s :\n",$subnet, $subnetn, $smask if $verbose;
 #   printf "\tSection=%s, vrf=%s (id=%s)\n",$ssectionid, $svrfname, $svrfid if $verbose;
    if ($ipver == 4) {
      $apref = new NetAddr::IP $subnet."\/".$smask;
    } else {
      $apref = new6 NetAddr::IP $subnet."\/".$smask;
    }
    $spref = sprintf "%s", $apref;
    $dbnet{$svrfname}{$spref}{'ineta'}=$subnetn;
    $dbnet{$svrfname}{$spref}{'inetn'}=$subnet;
    #$dbnet{$svrfname}{$spref}{'vrf'}=$svrfname;
    $dbnet{$svrfname}{$spref}{'mask'}=$smask;
    $dbnet{$svrfname}{$spref}{'vrfid'}=$svrfid;
    $dbnet{$svrfname}{$spref}{'perm'}=$spermissions;
    $dbnet{$svrfname}{$spref}{'netid'}=$sid;
    $dbnet{$svrfname}{$spref}{'secid'}=$ssectionid;
    $dbnet{$svrfname}{$spref}{'msubid'}=$smastersubnetid;
    $dbnet{$svrfname}{$spref}{'aggdev'}=$saggdev;
  }
   
  print "---------------------------------------\n";
  print "DBNET: \n";
  print Dumper %dbnet;
  print "---------------------------------------\n";
  

  for my $key (sort keys %tnet ) {
  # vrf
    if ($vpn eq '*') {
      $dvpn = $key; 
      $tvpn = $key;
    } elsif ($vpn eq $key) {
      $tvpn = $vpn;
    } else {
      next;
    }
    printf ("TN key = \'%s\'; VPN=\'%s\'; TVPN=\'%s\'\n", $key, $vpn, $tvpn);
    # Proceed only if matches a given vrf
      # Form an array of DB subnets for a given vrf 
      #my @sodbneta = sort {ipnetSort ($a,$b) } keys %{$dbnet{$dvpn}};
      my @sdbneta = keys %{$dbnet{$dvpn}};
      my @msiddbneta = sort { $dbnet{$dvpn}{$a}{'msubid'} <=> $dbnet{$dvpn}{$b}{'msubid'} } keys %{$dbnet{$dvpn}};
      print "*******************************\n";
      print "Sorted by msid DBNET\n";
      print Dumper @msiddbneta;
      print "*******************************\n";
      printf "Processing vrf '%s'...\n", $key ;
      # Form an array of snmp-based 'live' subnets for a given vrf 
      my @stneta = sort {ipnetSort ($a,$b) } keys %{$tnet{$key}};
      #my @sotneta = keys %{$tnet{$key}};
      # Add a snmp net into DB array if one is not there 
      foreach my $ka (@stneta) {
        if( !grep { $sdbneta[$_] eq $ka } 0 .. $#sdbneta ){
          push(@sdbneta, $ka) ;
        } 
      }
      # Make resulted array sorted
      @sdbneta = sort {ipnetSort ($a,$b) } @sdbneta;
      print "New tree, sorted\n";
      print "*******************************\n";
      print Dumper @sdbneta;
      print "*******************************\n";
      #undef @sotneta;
  
      for (my $i=0; $i<=$#sdbneta; $i++) {
        for (my $y=$i+1; $y <= $#sdbneta; $y++) {
          if(issubparent($sdbneta[$i],$sdbneta[$y])) {
            $dbnet{$dvpn}{$sdbneta[$y]}{'parent'} = $sdbneta[$i];
            push @{$dbnet{$dvpn}{$sdbneta[$i]}{'child'}}, $sdbneta[$y];
          }
          else {
            # No parent - put onto the tree's top 
          }
        }
      }
    
      #my $newdbrow = 0;
      print "*******************************\n";
      print "DNET vrf '$dvpn'\n";
      print Dumper $dbnet{$dvpn};
      print "*******************************\n";
    
      foreach my $key2 (@stneta) {
        next if ($key2 =~ /^(127\.|2[2-5].\.)/); 
        if (($opt{'r'}) and (issubparent($opt{'r'},$key2)) or (!($opt{'r'}))) {
          printf "\tProcessing subnet %s...\n", $key2;
          # subnet (A)
          if ($dbnet{$dvpn}{$key2}{'netid'}) {
            vout("\t\t in the DB. Try to add IP'es...");  
            # if the subnet is already in the DB 
            # fill this subnet with IP'es
            for my $ip (sort keys %{$tnet{$key}{$key2}{'iplist'}}) {
              printf "== %s, %s, %s, %s ==\n", $dbnet{$dvpn}{$key2}{'netid'}, $ip, $tnet{$key}{$key2}{'iplist'}{$ip},fqfd($tnet{$key}{$key2}{'iplist'}{$ip});
              if (!ipaddrdbin ($dbnet{$dvpn}{$key2}{'netid'}, $ip, $tnet{$key}{$key2}{'iplist'}{$ip},fqfd($tnet{$key}{$key2}{'iplist'}{$ip}))) {
                vout(sprintf "\t\tCouldn't insert the IP %s (%s)! Ignoring", $ip, $tnet{$key}{$key2}{'iplist'}{$ip});  
              } else {
                vout(sprintf "\t\t++ %s (%s)", $ip, $tnet{$key}{$key2}{'iplist'}{$ip});
              }
            } 
            # done w/ subnet
          } else {
            # If there is no such a subnet
            
            # parent network exists - insert a nested subnet 
            vout(sprintf "\tAdding the new subnet %s (%s)...", $key2, $tnet{$key}{$key2}{'inetn'});
              my ($pasecid, $panetid,$paperm, $paaggdev, $pamask, $paineta, $pavrf, $pavrfid);
              if (($dbnet{$dvpn}{$key2}{'parent'}) and ($dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'secid'})) {
                $pasecid = $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'secid'} ;
              } else { 
                $pasecid = $dsecid;
              }   
              if (($dbnet{$dvpn}{$key2}{'parent'}) and ($dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'netid'})) {
                $panetid = $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'netid'} ;
              } else { 
                $panetid = 0;
              }
              if (($dbnet{$dvpn}{$key2}{'parent'}) and ($dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'perm'})) {
                $paperm = $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'perm'} ;
              } else { 
                $paperm = $defpermissions;
              }
              if (($dbnet{$dvpn}{$key2}{'parent'}) and ($dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'aggdev'})) {
                $paaggdev = $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'aggdev'} ;
              } else { 
                $paaggdev = "-";
              }
              if (($dbnet{$dvpn}{$key2}{'parent'}) and ($dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'ineta'})) {
                $paineta = $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'ineta'} ;
              } else { 
                $paineta = "None";
              }
              if (($dbnet{$dvpn}{$key2}{'parent'}) and ($dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'mask'})) {
                $pamask = $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'mask'} ;
              } else { 
                $pamask = "None";
              }
              if (($dbnet{$dvpn}{$key2}{'parent'}) and ($dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'vrf'})) {
                $pavrf = $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'vrf'} ;
              } else { 
                # $pavrf = $key;
                $pavrf = $dvpn;
              }
              if (($dbnet{$dvpn}{$key2}{'parent'}) and ($dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'vrfid'})) {
                $pavrfid = $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'parent'}}{'vrfid'} ;
              } else {
              #if ($dbvrf{$key}) {
              #    $pavrfid = $dbvrf{$key};
                  $pavrfid = $dbvrf{$dvpn};
              #}
              #  else {
              #     $pavrfid = 0;
              #  }
              }
              if (subnetdbin ($tnet{$key}{$key2}{'inetn'},$tnet{$key}{$key2}{'mask'}, $pasecid, $tnet{$key}{$key2}{'descr'}, $pavrfid, $panetid, $paperm, $paaggdev)) {
                vout(sprintf "\t\t Done. Parent <- %s\/%s", $paineta, $pamask);
                #Check if subnet has been inserted
                #  ** CHECK **
                printf "Data for checknewtnetindb: %s,%s,%s,%s,%s\n", $tnet{$key}{$key2}{'inetn'},$tnet{$key}{$key2}{'mask'}, $pasecid, $pavrfid, $pavrf;
                if (checknewtnetindb($tnet{$key}{$key2}{'inetn'},$tnet{$key}{$key2}{'mask'}, $pasecid, $pavrfid)) {
                  #$newdbrow = 1;
                  # check if the former tree needs to be updated
                  if ($dbnet{$dvpn}{$key2}{'child'}) {
                  print "Dump 'CHILD'\n";
                  print Dumper $dbnet{$dvpn}{$key2}{'child'};
                  print "----------------------------\n";
                    foreach my $c ($dbnet{$dvpn}{$key2}{'child'}) {
                      if ( grep { $dbnet{$dvpn}{$key2}{'child'}{$c} eq  $msiddbneta[$_] } 0 .. $#msiddbneta) { 
                        print "Subnet %s [id=%s] new child - %s\/%s with id = %s\n", $key2, $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'child'}{$c}}{'ineta'}, $dbnet{$dvpn}{$key2}{'netid'} , $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'child'}{$c}}{'mask'}, $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'child'}{$c}}{'netid'}; 
                        if (!updatechildsubnet($dbnet{$dvpn}{$key2}{'netid'}, $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'child'}{$c}}{'netid'})) {
                          vout(sprintf "\t\tCouldn't update subnetwork tree: parent=>%s/%s, child=>%s/%s! Ignoring subnet",$dbnet{$dvpn}{$key2}{'ineta'},$dbnet{$dvpn}{$key2}{'mask'}, $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'child'}{$c}}{'ineta'}, $dbnet{$dvpn}{$dbnet{$dvpn}{$key2}{'child'}{$c}}{'mask'});
                          next;
                        }
                      }
                    }
                  }
                  for my $ip (sort keys %{$tnet{$key}{$key2}{'iplist'}}) {
                    printf "== %s, %s, %s, %s ==\n", $dbnet{$dvpn}{$key2}{'netid'}, $ip, $tnet{$key}{$key2}{'iplist'}{$ip},fqfd($tnet{$key}{$key2}{'iplist'}{$ip});
                  #for my $ip (sort $tnet{$key}{$key2}{'iplist'}) 
                    if (!ipaddrdbin ($dbnet{$dvpn}{$key2}{'netid'}, $ip, $tnet{$key}{$key2}{'iplist'}{$ip},fqfd($tnet{$key}{$key2}{'iplist'}{$ip}))) {
                      vout(sprintf "\t\tCouldn't insert the IP %s (%s)! Ignoring", $ip, $tnet{$key}{$key2}{'iplist'}{$ip});  
                    } else {
                      vout(sprintf "\t\t++ %s (%s)", $ip, $tnet{$key}{$key2}{'iplist'}{$ip});
                    }
                  } 
                } else {
                    vout(sprintf "\t\tCann't find the new network %s to update the subnet tree! Go to the next subnet", $key2);
                } 
              } else {
                # Failed to install subnet - break w/ current vrf
                last;
              }
          }
        # done w/ subnet       
        }
      }
      vout(sprintf("Done w/ vrf '%s'", $key));
  }
  $sth->finish();
  $dbh->disconnect();
  exit 0;

# End of main routine
#########################################################################
#
sub subnetdbin {
  # Create a new subnetwork
  # Use global DB handlers
  local $dbh->{RaiseError};
  my ($subnet,$mask,$sectionId,$description,$vrfId,$masterSubnetId,$permissions,$AggDev) = @_;
  my $sql = "INSERT INTO subnets (subnet,mask,sectionId,description,vrfId,masterSubnetId,permissions,editDate,AggDev) VALUES (?,?,?,?,?,?,?,now(),?);";
  my $sqlstr= "INSERT INTO subnets (subnet,mask,sectionId,description,vrfId,masterSubnetId,permissions,editDate,AggDev) VALUES (%s,%s,%s,'%s',%s,%s,'%s',now(),'%s');";

  my $ih = $dbh->prepare($sql); 
  if (!$ih) {
    vout(sprintf "Couldn't prepare query $sqlstr", $subnet,$mask,$sectionId,$description,$vrfId,$masterSubnetId,$permissions,$AggDev);  
    return 0;
  }
  if (!$opt{'d'}) {
    if (!$ih->execute($subnet,$mask,$sectionId,$description,$vrfId,$masterSubnetId,$permissions,$AggDev)) {
      vout(sprintf "Couldn't execute query $sqlstr", $subnet,$mask,$sectionId,$description,$vrfId,$masterSubnetId,$permissions,$AggDev);  
      return 0;
    }  
  } else {
    vout("D: =subnetdbin= dry run");  
  }
  vout (sprintf "DB: $sqlstr", $subnet,$mask,$sectionId,$description,$vrfId,$masterSubnetId,$permissions,$AggDev);
  return 1;
}

sub ipaddrdbin {
  # Fill a given subnet w/ ip address
  # Use global DB handlers
  my ($subnetId, $ipaddr,$description,$dnsname) = @_;
  local $dbh->{RaiseError};
  #my $sql = "INSERT INTO ipaddresses (subnetId,ip_addr,description,dns_name,editDate) VALUES (?,INET_ATON(?),?,?,now());";
  my $sql = "INSERT INTO ipaddresses (subnetId,ip_addr,description,dns_name,editDate) VALUES (?,INET_ATON(?),?,?,now()) ON DUPLICATE KEY UPDATE description=VALUES(description), dns_name=VALUES(dns_name),editDate=now();";
  my $sqlstr = "INSERT INTO ipaddresses (subnetId,ip_addr,description,dns_name,editDate) VALUES (%s,INET_ATON('%s'),'%s','%s',now()) ON DUPLICATE KEY UPDATE;";
  my $ih = $dbh->prepare_cached($sql); 
  if (!$ih) {
    vout(sprintf "Couldn't prepare query $sqlstr", $subnetId, $ipaddr,$description,$dnsname);  
    return 0;
  }
  if (!$opt{'d'}) {
    if (!$ih->execute($subnetId, $ipaddr,$description,$dnsname)) {
      vout(sprintf "Couldn't execute query $sqlstr", $subnetId, $ipaddr,$description,$dnsname);  
      return 0;
    }
  } else {
    vout("D: =ipaddrdbin= dry run");  
  }  
  vout (sprintf "DB: $sqlstr", $subnetId, $ipaddr,$description,$dnsname);
  return 1;
}

sub updatechildsubnet {
  my (%p,%c) = @_;
  # Update a subnet in the tree to form child
  # Use global DB handlers
  my ($parentsubnetid, $childsubnetid) = @_;
  local $dbh->{RaiseError};
  my $sql = "UPDATE subnets SET masterSubnetId=? WHERE id=?;";
  my $sqlstr = "UPDATE subnets SET masterSubnetId=%s WHERE id=%s;";
  my $ih = $dbh->prepare($sql);
  if (!$ih) {
    vout(sprintf "Couldn't prepare query $sqlstr", $parentsubnetid, $childsubnetid);
    return 0;
  }
  if (!$opt{'d'}) {
    if (!$ih->execute($parentsubnetid, $childsubnetid)) {
      vout(sprintf "Couldn't execute query $sqlstr", $parentsubnetid, $childsubnetid);
      return 0;
    }
  } else {
    vout("D: =updatechildsubnet= dry run");  
  }
  vout (sprintf "DB: $sqlstr", $parentsubnetid, $childsubnetid);
  return 1;
} 

#sub checkgrannyisthere 
sub checknewtnetindb {
  # Assure the new inserted network (%granny) has been put into DB
  # Returns the hash of '%dbnet' type of newly inserted data
  # Use global DB handlers
  my ($ssubnet, $smask, $ssectionId, $svrfid) = @_;
  my %xgranny;
  local $dbh->{RaiseError};
  my ($sql, $sqlstr);
  if ($ipver == 4) {
    $sql = "SELECT DISTINCT(s.id), s.subnet,INET_NTOA(s.subnet) AS ipv4addr, s.mask, s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev FROM subnets s WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) < '4294967295' AND s.subnet=? AND s.mask=? AND s.sectionId=? and s.vrfid=?;";
    $sqlstr = "SELECT DISTINCT(s.id), s.subnet,INET_NTOA(s.subnet) AS ipv4addr, s.mask, s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev FROM subnets s WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) < '4294967295' AND s.subnet=%s AND s.mask=%s AND s.sectionId=%s and s.vrfid=%s;";
  } else {
    # IPv6
    $sql = "SELECT DISTINCT(s.id), s.subnet,cast(`subnet` as UNSIGNED) as ipv6addr, s.mask, s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev FROM subnets s WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) > '4294967295' AND s.subnet=? AND s.mask=? AND s.sectionId=? and s.vrfid=?;";
    $sqlstr = "SELECT DISTINCT(s.id), s.subnet,cast(`subnet` as UNSIGNED) as ipv6addr, s.mask, s.sectionId,s.vrfId,s.masterSubnetId,s.permissions,s.AggDev FROM subnets s WHERE isFolder=0 AND CAST(`subnet` AS UNSIGNED) > '4294967295' AND s.subnet=%s AND s.mask=%s AND s.sectionId=%s and s.vrfid=%s;";
  }

  my @k = grep { $dbvrf{$_} == $svrfid } keys %dbvrf;
  my $svrfname = ""; 
  $svrfname = $k[0] if (@k); 
  print "checknewtnetindb: svrfname=$svrfname\n";
  my $ih = $dbh->prepare($sql);
  if (!$ih) {
    vout(sprintf "Couldn't prepare query $sqlstr", $ssubnet, $smask, $ssectionId, $svrfid);
    return 0;
  }
  if (!$ih->execute($ssubnet, $smask, $ssectionId, $svrfid)) {
    vout(sprintf "Couldn't execute query $sqlstr: %s", $ssubnet, $smask, $ssectionId, $svrfid, $ih->errstr);
    return 0;
  }  
  if ($ih->rows == 1) {
    vout (sprintf "DB: $sqlstr", $ssubnet, $smask, $ssectionId, $svrfid);
    my ($xid, $xsubnet, $xsubnetn,$xmask,$xsectionid,$xvrfid,$xmastersubnetid,$xpermissions,$xaggdev) = 
    $ih->fetchrow_array();  # return single row only
    my ($spref, $apref);                      
    vout(sprintf "Subnet %s (%s)/%s with id=%s\n",$xsubnet, $xsubnetn, $xmask,$xid);
    if ($ipver == 4) {          
      $apref = new NetAddr::IP $xsubnet."\/".$xmask;
    } else {
      $apref = new6 NetAddr::IP $xsubnet."\/".$xmask;
    }                            
    $spref = sprintf "%s", $apref;
    $dbnet{$svrfname}{$spref}{'ineta'}=$xsubnetn;
    $dbnet{$svrfname}{$spref}{'inetn'}=$xsubnet;
    $dbnet{$svrfname}{$spref}{'vrf'}=$svrfname;
    $dbnet{$svrfname}{$spref}{'mask'}=$xmask;
    $dbnet{$svrfname}{$spref}{'vrfid'}=$xvrfid;
    $dbnet{$svrfname}{$spref}{'perm'}=$xpermissions;
    $dbnet{$svrfname}{$spref}{'netid'}=$xid;            
    $dbnet{$svrfname}{$spref}{'secid'}=$xsectionid;   
    $dbnet{$svrfname}{$spref}{'msubid'}=$xmastersubnetid;
    return 1;
  } else {
    vout(sprintf "The DB doesn't contain a record with subnet %s/%s in vrf \"%s\"", todotquad($ssubnet), $smask,  $svrfname);
    return 0;
  }
}

sub vout {
  printf "%s\n",$_[0] if $verbose;
}

sub gen_interf_descr
{
  my ($intrf, $dns) = @_;
  $_ = $intrf;
  if ($intrf =~ /Security Appliance/) { ($intrf) = $intrf=~ /.*\'(.*?)\'.*/; }
  # Cisco Load Balancer
  if ($intrf =~ /circuit\-/) { $intrf =~ s/(circuit-|[\(\)])//g; }
  #Extreme
  if ($intrf =~ /rtif/) { $intrf =~ s/[\(\)]/\./; $intrf =~ s/[\)]//;$intrf =~ s/(\/.*)//; }
  
  $intrf =~ s/^(.*?) .*$/$1/g;
  $intrf =~ s/(\-802\.1Q)//g;
  $intrf =~ tr/[A-Z]/[a-z]/;
  my @s3 = ("eth-trunk");
  if (grep { $intrf =~ /$_/ } @s3) {
    $intrf =~ s/^([A-Za-z][A-Za-z][A-Za-z])[A-Za-z-]*/$1/g;
  } else {
    $intrf =~ s/^([A-Za-z][A-Za-z])[A-Za-z-]*/$1/g;
  }
  $intrf =~ s/[\/\.\:\-]$//g;
  $intrf =~ s/^[\/\.\:\-]//g;
  if ($dns) {
    $intrf =~ s/(.*?)[\.\:](.*)/$2-$1/g;
    $intrf =~ s/[\/\.\:]/-/g;
  }
  return $intrf;
}

sub fqfd {
  # input - a string '<device> <interface>'
  my $str = $_[0]; 
  # chomp it first;
  $str =~ s/^[\s+]//;
  $str =~ s/[\s+]$//;
  my ($d, $i) = split /\s/, $str;
  $d =~ tr/[A-Z]/[a-z]/;
  $d =~ tr/[\_]/[\-]/;
  # trim domain name part of the device name
  $d =~ s/(.*?)\..*$/$1/;
  return gen_interf_descr($i,1)."\.".$d;
}

sub ipnetSort {
  my $ip = new NetAddr::IP $a;
  my $ip2 = new NetAddr::IP $b;
  if ($ip->numeric() < $ip2->numeric()) { return -1; }
  elsif ($ip->numeric() == $ip2->numeric()) {
    # Check masks len then
    if ($ip->masklen() < $ip2->masklen()) { return -1; }
    if ($ip->masklen() == $ip2->masklen()) { return 0; }
    if ($ip->masklen() > $ip2->masklen()) { return 1; }
  }
  elsif ($ip->numeric() > $ip2->numeric()) { return 1; }
}

sub issubparent {
  # Check whether $b is a child for $a 
  # $a,$b  = 'ip/mask'
  my ($a,$b) = @_;
  my $ip = new NetAddr::IP $a;
  my $ip2 = new NetAddr::IP $b;
  return 1 if ($ip2->within($ip));
  return 0; 
}

sub todotquad {
   # Given a binary int IP, returns dotted-quad (Reverse of ip2num)
   my $bin = shift;
   my $result = ''; # Empty string
   
   for (24,16,8,0){
       $result .= ($bin >> $_  & 255)  . '.';
   }
   chop $result; # Delete extra trailing dot
   return $result;
}


##
#sub rr { my $r = shift; $r =~ s/(\d+).*/$1/; return $r;}
#
#sub sort_ip_str{
#  my @unsorted = @_;
#  my @sorted = map  { $_->[0] }
#  sort { $a->[1] <=> $b->[1] }
#  ##map  { [$_, int sprintf("%03.f%03.f%03.f%03.f", split(/\./, $_))] }
#  map  { [$_, int sprintf("%03.f%03.f%03.f%03.f", eval { $_ =~ /.*#(.*)/; split(/\./,$1)} )] }
#             @unsorted;
#  return @sorted;
#}
#
#sub remove_tree_xl{
#  my $mdir = shift;
#  $mdir = abs_path($mdir);
#  return 1 if (!-d $mdir) or (!-e $mdir);
#  my @mfiles = <$mdir/*>;
#  #print "mdir = $mdir\n";
#  foreach my $mfile (@mfiles) {
#    next if $mfile =~ /^(\.|\.\.)$/;
#    #print "\tfile=$mfile\n";
#    if (-d $mfile) { 
#	remove_tree_xl($mfile);
#    }
#    else { 
#      unlink($mfile);
#    }
#  }
#  rmdir($mdir);  
#}
#
#sub gen_ptr_str
#{
#  my ( $ip, $intrf, $aRR, $replace, $ptrzone) = @_;
#  my ($host,$domain);
#  $domain = "";
#  my $ptr_name = $ip;
#  $ptr_name=~s/([\d]{1,3})\.([\d]{1,3})\.([\d]{1,3})\.([\d]{1,3})/$3.$2.$1.in-addr.arpa/g;
#  my $ht=$4;
#  $_ = $intrf;
#  if ($intrf =~ /Security Appliance/) { ($intrf) = $intrf=~ /.*\'(.*?)\'.*/; }
#  # Cisco Load Balancer
#  if ($intrf =~ /circuit\-/) { $intrf =~ s/(circuit-|[\(\)])//g; }
#  #Extreme
#  if ($intrf =~ /rtif/) { $intrf =~ s/[\(\)]/\./; $intrf =~ s/[\)]//;$intrf =~ s/(\/.*)//; }
#  
#  $intrf =~ s/^(.*?) .*$/$1/g;
#  $intrf =~ s/(\-802\.1Q)//g;
#  $intrf =~ s/^([A-Za-z][A-Za-z])[A-Za-z-]*/$1/g;
#  $intrf =~ s/[\/\.\:\-]$//g;
#  $intrf =~ s/^[\/\.\:\-]//g;
#  $intrf =~ s/(.*?)[\.\:](.*)/$2-$1/g;
#  $intrf =~ s/[\/\.\:]/-/g;
#  $intrf =~ tr/[A-Z]/[a-z]/;
#  return if (!$intrf);
#  $aRR =~ tr/[A-Z]/[a-z]/;
#  $host = $aRR;
#  if ($aRR =~ /\./) {
#    ($host,$domain)=$aRR=~/(.*?)\.(.*)/;
#  } else {
#    $domain = "defaultdomain";
#  }
#  $host =~ s/[_\/\.\:]/-/g;
#  $host = "unknowndevice" if (!$host);
#  ## printf "ARPA: %s\n",$ptr_name;
#  ##  printf "%s\tIN\tPTR\t%s.%s\n",$ht,$intrf,$aRR;
#  ##$ptrRR = sprintf("%s\tIN\tPTR\t%s\n",$ht,$aRR);
#  ##  push @{$ptrzone->{$ptr}},$ht."\tIN\tPTR\t".$host."\n";
#  #push @{$ptrzone->{$ptr_name}},$ht."\tIN\tPTR\t".$intrf.".".$aRR."\n";
#  #push @{$ptrzone->{$ptr_name}},$ht."\tIN\tPTR\t".$intrf.".".$host.".".$domain;
#  $domain = $replace if ($replace);
#  $domain = $domain."." if ($domain) and ($domain !~ /.*\.$/);
#  push @{$ptrzone->{$ptr_name}},$ht."\tIN\tPTR\t".$intrf.".".$host.".".$domain;
#  return;
#}
#
#sub gen_azone
#{
#  my ( $ip, $intrf, $replace, $vrf, $hostk, $aRR, $tmpzone) = @_;
#  my ($host, $zonename);
#  $host = $aRR;
#  if ($aRR =~ /\./) {
#    ($host,$zonename)=$aRR=~/(.*?)\.(.*)/;
#  } else {
#    $zonename = "defaultzone";
#  }
#  $host =~ s/[\/\.\:_]/-/g;
#  $host = lc($host);
#  $zonename = $replace if ($replace);
#  if (($vrf == 1) and ($intrf =~ /^([Ll]oopback1)$/ )) {
#    $tmpzone->{$zonename}{$aRR}[0]=$host."#".$ip;
#    return 1;
#  }
#  elsif (($vrf == 0) and ($intrf =~ /^([Ll]oopback0|[Vv]lan1)$/ )) {
#    $tmpzone->{$zonename}{$aRR}[0]=$host."#".$ip;
#    return 1;
#  }
#  elsif (($vrf == 0) and ($hostk =~ /$ip/)){
#    $tmpzone->{$zonename}{$aRR}[0]=$host."#".$ip;
#  }
#  return 0;
#}
#
#sub log_failed_host {
#  my $logfile = shift;
#  my @hosts = @_;
#    open LOGFILE, ">", "$logfile" or die "Can't log to $logfile\n";
#    foreach my $host (@hosts) {
#    	print LOGFILE "$host\n";
#    }
#    close LOGFILE;
#}

sub get_hostname
{
  my ($session, $location, $table) = @_;
  my $result = $session->var_bind_list();

  if (!defined $result) {
	printf "ERROR: Get request in 'get_hostname' failed for host '%s': %s.\n",
          $session->hostname(), $session->error() if $verbose;
	#push @failh, $session->hostname if ($log_failed_host); 
	return;
  }

  ##  printf "The host '%s' is %s.\n",
  ##       $session->hostname(), $result->{$HOSTNAME_OID};
  $table{$session->hostname()}{'hostname'}=$result->{$HOSTNAME_OID};
  $result = $session->get_table(
	-baseoid       => $ADDRESSES_OID,
     	-callback       => [ \&get_interface_id, \%table ],
  ### -callback       => [ \&get_interface_id, \%table ],
  );

  if (!defined $result) {
	printf "ERROR: Failed to queue get_table request for host '%s': %s.\n",
       		$session->hostname(), $session->error() if $verbose;
  }
  return;
}

sub get_interface_admin_status
{
  #my $ifAdminStatus=".1.3.6.1.2.1.2.2.1.7";
  #1.3.6.1.2.1.2.2.1.7   .250 = INTEGER: up(1)
  #^^^^^^^^^^^^^^^^^^^    ^^^           ^^^^^^
  # OID                   Index          Value
  my ($session, $table) = @_;
  my $result = $session->var_bind_list();

  if (!defined $result) {
        printf "ERROR: Get admin status request failed for host '%s': %s.\n",
          $session->hostname(), $session->error() if $verbose;
        return;
  }

  my @oids = $session->var_bind_names();
  my $next  = undef;
  while (@oids) {
    $next = shift @oids;
 ##      printf "NAME=%s\n", $next;
 ##      printf "Index=%s\n", $list->{$next};
    my $indx = $next;
    $indx =~ s/$ifAdminStatus\.//;
    $table{$session->hostname()}{'indexes'}{$indx}{'admstat'}=$result->{$next};
   }
  return;
}

sub get_interface_ipmask
{
  #.1.3.6.1.2.1.4.20.1.3.192.168.109.1 = IpAddress: 255.255.255.252
  #.1.3.6.1.2.1.4.20.1.3.192.168.109.9 = IpAddress: 255.255.255.252
  #^^^^^^^^^^^^^^^^^^^^^    ^^^^^                       ^^^^^^
  # OID                   IP Address                     Value
  my ($session, $table2) = @_;
  my $result = $session->var_bind_list();

  if (!defined $result) {
        printf "ERROR: Get interface ip mask request failed for host '%s': %s.\n",
          $session->hostname(), $session->error() if $verbose;
        return;
  }

  my @oids = $session->var_bind_names();
  my $next  = undef;
  my $i=0;
  while (@oids) {
    $next = shift @oids;
 ##      printf "NAME=%s\n", $next;
 ##      printf "Index=%s\n", $list->{$next};
    my $ip = $next;
    $ip =~ s/$ipAdEntNetMask\.//;
    $table2{$session->hostname()}{$ip}{'mask'}=$result->{$next};
    $table2{$session->hostname()}{$ip}{'id'}=$i;
    $i++;
   }
  return;
}

sub get_interface_description
{
  #.1.3.6.1.2.1.2.2.1.2.259 = STRING: GigabitEthernet8/1/3.4035
  #^^^^^^^^^^^^^^^^^^    ^^^           ^^^^^^^^^^^^^^^^^^^^^^^^^
  # OID                   Index             Value
  my ($session, $table) = @_;
  my $result = $session->var_bind_list();

  if (!defined $result) {
        printf "ERROR: Get vrf request failed for host '%s': %s.\n",
          $session->hostname(), $session->error() if $verbose;
        return;
  }

  my @oids = $session->var_bind_names();
  my $next  = undef;
  while (@oids) {
    $next = shift @oids;
 ##      printf "NAME=%s\n", $next;
 ##      printf "Index=%s\n", $list->{$next};
    my $indx = $next;
    $indx =~ s/$ifDescrOid\.//;
    $table{$session->hostname()}{'indexes'}{$indx}{'descr'}=$result->{$next};
   }
  return;
}


sub get_vrf_int
{
  #$mplsVpnVrfTableCisco="1.3.6.1.3.118.1.2.1.1.6";
  #$VpnServiceIdTableHuawei="1.3.6.1.4.1.2011.5.25.177.2.2.1";
  #.1.3.6.1.4.1.2011.5.25.177.2.2.1.    2.3.  117.115.114 = Gauge32: 0
  # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^   ^^^^^^^^^^^ 
  # OID                                junk   array [chars] 

  #.1.3.6.1.3.118.1.2.1.1.6.   2.    71.98.9 =     INTEGER: active(1)
  # ^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^   ^^^^^^^^ 
  # OID                       junk   array [chars] 
  
  my ($session, $location, $table) = @_; 
  my $result = $session->var_bind_list();

  if (!defined $result) {
        printf "ERROR: Get vrf request failed for host '%s': %s.\n",
          $session->hostname(), $session->error() if $verbose;
        return;
  }
  my $sl = 33; # default - huawei
  $sl = 24 if ($location eq $mplsVpnVrfTableCisco);
    
  my @oids = $session->var_bind_names();
  my $next  = undef;
 
   while (@oids) {
        $next = shift @oids;
        my @karr = split(/\./,substr($next, $sl));
	shift(@karr);
        my $int_id = pop(@karr);   # Showstopper, no index shown in perl???
        my $vrfname = "";
        foreach my $char (@karr){   # VRF Name is OID...
            $vrfname .= chr($char);
        }
	$table{$session->hostname()}{'indexes'}{$int_id}{'vrf'}=$vrfname;
	if (!grep {$vrfname eq $_} @{ $table{$session->hostname()}{'vrfs'} } ) {
    	  push @{$table{$session->hostname()}{'vrfs'} },$vrfname;
    	}
   }
  return;
}

sub get_interface_descr
{     
  my ($session, $descroid, $ip, $table) = @_;
  my $result = $session->var_bind_list();
  if (!defined $result) {
  	printf "ERROR: Get request failed for host '%s': %s.\n",
        	$session->hostname(), $session->error() if $verbose;
        return;
  }
  $table{$session->hostname()}{'indexes'}{$descroid}{'descr'}=$result->{${ifDescrOid}.".".$descroid};
  return;
}

sub get_interface_id
{
  my ($session, $table,$table2) = @_;

  my $list = $session->var_bind_list();
  if (!defined $list) {
  	printf "ERROR: %s\n", $session->error() if $verbose;
        return;
  }

  # Loop through each of the OIDs in the response and assign
  # the key/value pairs to the reference that was passed with
  # the callback.  Make sure that we are still in the table
  # before assigning the key/values.

  my @names = $session->var_bind_names();
  my $next  = undef;

  while (@names) {
  	$next = shift @names;
##	printf "NAME=%s\n", $next;
##	printf "Index=%s\n", $list->{$next};
	my $ip=$next;
	$ip =~ s/$ADDRESSES_OID\.//;
	my $index = $list->{$next};
	$table{$session->hostname()}{'indexes'}{$index}{'ip'}=$ip;
	$table2{$session->hostname()}{$ip}{'idx'}=$index;
##	print "X IP=$table{$session->hostname()}{'indexes'}{$index}{'ip'}\n";
	##printf "List=%s\n",  ${IFDESCR_OID}.".".$list->{$next};
###        my $list2 = $session->get_request(
###		-varbindlist => [  ${IFDESCR_OID}.".".$index ],
###        	-callback    => [ \&get_interface_descr,$index,$ip,\%table ],
###        );
###
###        if (!defined $list2) {
###        	printf "ERROR: Failed to queue get request for host '%s': %s.\n",
###                $session->hostname(), $session->error() if $verbose;
###        }
  }	
  return;
}
#   sub set_callback
#   {
#      my ($session) = @_;
#
#      my $result = $session->var_bind_list();
#
#      if (defined $result) {
#         printf "The sysContact for host '%s' was set to '%s'.\n",
#                $session->hostname(), $result->{$OID_sysContact};
#         printf "The sysLocation for host '%s' was set to '%s'.\n",
#                $session->hostname(), $result->{$OID_sysLocation};
#      } else {
#         printf "ERROR: Set request failed for host '%s': %s.\n",
#                $session->hostname(), $session->error();
#      }
#
#      return;
#   }

sub isip{
  my $testip = shift;
  $testip =~ /^([\d]{1,3})\.([\d]{1,3})\.([\d]{1,3})\.([\d]{1,3})$/;
  #if ((int ($1) > 254) or (int ($1) < 1) or (int($2) > 255) or (int ($1) < 0) or (int($3) =< 255) or (int ($3) < 0) or (int($4) =< 255) or (int ($4) < 0)) {   
  if ((int $1 > 254) or (int $1 < 1) or (int $2 > 255) or (int $2 < 0) or (int $3 > 255) or (int $3 < 0) or (int $4 > 255) or (int $4 < 0)) {
    print "Error in IP address!\n";
    return 0;
  }
    return 1;
}

sub mkHostList {
  my $subFileName = shift;
  my %subHostList;
  open(my $fh, $subFileName) or die "Could not open file '$subFileName' $!";

  while (my $row = <$fh>) {
    chomp $row;
    next if $row =~ /^(\s*?)#/;
    my @a = split /\t+/,$row;
    if (@a) {
      #print "Host=".$a[0]."IP=".$a[1]."\n";
      $subHostList{$a[0]}=$a[1];
    }
  }
  return %subHostList;
}

sub HELP {
  print "\n";
  print "usage: dnsgen.pl [-I|-l <option(s)>] [-v|-d|-h]\n";
  print "  -I <first_ip>:<last_ip>    Put the range for hosts to query (IPv4)\n";
  print "  -l <logfile>    Log host snmp query for which was failed to <logfile> \n";
  print "  -v    verbose output\n";
  print "  -d    dry run (do not do anything with file writing, only query hosts and process results)\n";
  print "  -h    This help\n";
  exit 0;
}
