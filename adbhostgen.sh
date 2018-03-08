#!/bin/sh
# File: adbhostgen.sh
#
# Script to generate massive block lists for DD-WRT
#
# https://github.com/m-parashar/adbhostgen
# https://gist.github.com/m-parashar/ee38454c27f7a4f4e4ab28249a834ccc
# https://www.dd-wrt.com/phpBB2/viewtopic.php?t=307533
#
# Thanks: Pi-hole, Christopher Vella, Arthur Borsboom, users, and all the list providers.
#
# AUTHOR: Manish Parashar
# Last updated: 2018/03/08

VERSION="20180308"

# define aggressiveness: [ 0 | 1 ]
# 0: toned down, tuxedo wearing ad-slaying professional mode
# 1: ramped up, stone cold ad-killing maniac mode
BLITZ=0

# where ads go to die
supermassiveblackhole="0.0.0.0"

# define dnsmasq directory and path
MPDIR='/jffs/dnsmasq'
TMPDIR='/tmp'

# dnsmasq hosts & domain files
mphosts="${MPDIR}/mphosts"
tmphosts="${TMPDIR}/mphosts.tmp"

# temporary dnsmasq hosts & domain files
mpdomains="${MPDIR}/mpdomains"
tmpdomains="${TMPDIR}/mpdomains.tmp"

# blacklist file: a list of blacklisted domains one per line
blacklist="${MPDIR}/blacklist"

# whitelist file: a list of whitelisted domains one per line
whitelist="${MPDIR}/whitelist"

# user's custom blacklist file: a list of blacklisted domains one per line
myblacklist="${MPDIR}/myblacklist"

# user's custom whitelist file: a list of whitelisted domains one per line
mywhitelist="${MPDIR}/mywhitelist"

# curl certificates and options
export CURL_CA_BUNDLE="${MPDIR}/ca-bundle.crt"
alias MPGET='curl -s -k'
alias MPGETSSL='curl -s --capath ${MPDIR} --cacert cacert.pem'
alias MPGETMHK='curl -s -A "Mozilla/5.0" -e http://forum.xda-developers.com/'
if [ ! -x /usr/bin/curl ] ; then
	echo ">>> WARNING: cURL not installed. Using local mpcurl for downloads."
	if [ ! -x ${MPDIR}/mpcurl ] ; then
		echo ">>> ERROR: mpcurl not found. If file exists, chmod +x it and run this script again."
		echo ">>> ERROR: cannot continue. Exiting."
		exit 1
	fi
	alias MPGET='${MPDIR}/mpcurl -s -k'
	alias MPGETSSL='${MPDIR}/mpcurl -s --capath ${MPDIR} --cacert cacert.pem'
	alias MPGETMHK='${MPDIR}/mpcurl -s -A "Mozilla/5.0" -e http://forum.xda-developers.com/'
fi

if [ "$SELF_LOGGING" != "1" ]; then
    # The parent process will enter this branch and set up logging

    # Create a named piped for logging the child's output
    PIPE=/tmp/tmp.fifo
    mkfifo $PIPE

    # Launch the child process without redirected to the named pipe
    SELF_LOGGING=1 sh $0 $* >$PIPE &

    # Save PID of child process
    PID=$!

    # Launch tee in a separate process
    tee ${MPDIR}/mphosts.log <$PIPE &

    # Unlink $PIPE because the parent process no longer needs it
    rm $PIPE

    # Wait for child process running the rest of this script
    wait $PID

    # Return the error code from the child process
    exit $?
fi

if ping -q -c 1 -W 1 google.com >/dev/null; then

	TIMERSTART=`date +%s`
	echo "============================================"
	echo "|           adbhostgen for DD-WRT          |"
	echo "| https://github.com/m-parashar/adbhostgen |"
	echo "|      Copyright 2018 Manish Parashar      |"
	echo "============================================"
	echo "        `date`"
	echo "# VERSION: $VERSION"
	echo "# Cranking up the ad-slaying engine"

	if [ ! -s ca-bundle.crt ] || [ ! -s cacert.pem ] || [ $(date +%A) = "Monday" ]; then
		echo "> Downloading / updating cURL certificates for secure communication"
		MPGETSSL --remote-name --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem || MPGET --remote-name --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem
		MPGETSSL https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt > ca-bundle.crt || MPGET https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt
	fi

	echo "> Updating official blacklist and whitelist files"
	MPGET https://raw.githubusercontent.com/m-parashar/adbhostgen/master/blacklist > $blacklist
	MPGET https://raw.githubusercontent.com/m-parashar/adbhostgen/master/whitelist > $whitelist

	if [ $BLITZ -eq 1 ]; then
		echo "# BLITZ mode: ON"
	else
		echo "# BLITZ mode: OFF"
	fi

	echo "> Processing StevenBlack lists"
	MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sed 's/#.*$//;/^$/d' | awk '{print $2}' > $tmphosts
	MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/tyzbit/hosts | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/oznu/dns-zone-blacklist/master/dnsmasq/dnsmasq.blacklist | sed 's/#.*$//;/^$/d' | grep -v "::" > $tmpdomains

	echo "> Processing notracking blocklists"
	MPGETSSL https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt | grep -v "::" | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt | sed 's/#.*$//;/^$/d' | grep -v "::" >> $tmpdomains

	echo "> Processing Cameleon list"
	MPGET http://sysctl.org/cameleon/hosts | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts

	echo "> Processing hosts-file ad_servers list"
	MPGETSSL https://hosts-file.net/ad_servers.txt | grep -v "::1" | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts

	echo "> Processing Disconnect.me lists"
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt | sed 's/#.*$//;/^$/d' >> $tmphosts
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt | sed 's/#.*$//;/^$/d' >> $tmphosts
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt | sed 's/#.*$//;/^$/d' >> $tmphosts
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt | sed 's/#.*$//;/^$/d' >> $tmphosts

	echo "> Processing quidsup/notrack lists"
	MPGETSSL https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt | sed 's/#.*$//;/^$/d' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/quidsup/notrack/master/malicious-sites.txt | sed 's/#.*$//;/^$/d' >> $tmphosts

	echo "> Processing MalwareDomains lists"
	MPGETSSL https://mirror1.malwaredomains.com/files/justdomains >> $tmphosts
	MPGETSSL https://mirror1.malwaredomains.com/files/immortal_domains.txt | grep -v "#" >> $tmphosts

	echo "> Processing Securemecca list"
	MPGETSSL https://hostsfile.org/Downloads/hosts.txt | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts

	echo "> Processing abuse.ch blocklists"
	MPGETSSL https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist | grep -v "#" >> $tmphosts
	MPGETSSL https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | grep -v "#" >> $tmphosts

	echo "> Processing adaway list"
	MPGETSSL https://adaway.org/hosts.txt | grep -v "::1" | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts

	echo "> Processing Easylist & others"
	MPGETSSL https://v.firebog.net/hosts/AdguardDNS.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/Airelle-hrsk.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/Airelle-trc.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/BillStearns.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/Easylist.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/Easyprivacy.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/Kowabit.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/Prigent-Ads.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/Prigent-Malware.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/Prigent-Phishing.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/Shalla-mal.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/static/SamsungSmart.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://v.firebog.net/hosts/static/w3kbl.txt | sed -e 's/#.*$//' -e '/^$/d' >> $tmphosts
	MPGETSSL https://www.dshield.org/feeds/suspiciousdomains_High.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://www.dshield.org/feeds/suspiciousdomains_Medium.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://www.dshield.org/feeds/suspiciousdomains_Low.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/hosts | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/tyzbit/hosts/master/data/tyzbit/hosts | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts | grep -v "::1" | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt | grep -v "#" >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win10/spy.txt | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list | grep -v "#" >> $tmphosts

	if [ $BLITZ -eq 1 ]; then
		echo "> Processing winhelp2002 list"
		MPGET http://winhelp2002.mvps.org/hosts.txt | grep -v "::1" | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts

		echo "> Processing Yoyo list"
		MPGETSSL -d mimetype=plaintext -d hostformat=unixhosts https://pgl.yoyo.org/adservers/serverlist.php? | grep -v "#" | awk '{print $2}' >> $tmphosts

		echo "> Processing HostsFile.mine.nu list"
		MPGETSSL https://hostsfile.mine.nu/hosts0.txt | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts

		echo "> Processing Mahakala list"
		MPGETMHK http://adblock.mahakala.is/hosts | grep -v "#" | awk '{print $2}' >> $tmphosts

		echo "> Processing someonewhocares list"
		MPGET http://someonewhocares.org/hosts/zero/hosts | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts

		echo "> Processing mat1th list"
		MPGETSSL https://raw.githubusercontent.com/mat1th/Dns-add-block/master/hosts | grep -v "#" | awk '{print $2}' >> $tmphosts

		echo "> Processing ADZHOSTS list"
		MPGETSSL https://adzhosts.fr/hosts/adzhosts-mac-linux.txt | grep -v "::1" | sed 's/#.*$//;/^$/d' | awk '{print $2}' >> $tmphosts
	fi

	fileSize=`du -h $tmphosts | awk '{print $1}'`
	echo "# Size of $tmphosts before formatting: $fileSize"
	fileSize=`du -h $tmpdomains | awk '{print $1}'`
	echo "# Size of $tmpdomains before formatting: $fileSize"

	echo "> Processing blacklist and whitelist files"
	sed -r 's/^\s*//; s/\s*$//; /^$/d' $blacklist | sort -u > tmpbl && cp tmpbl $blacklist
	sed -r 's/^\s*//; s/\s*$//; /^$/d' $whitelist | sort -u > tmpwl && cp tmpwl $whitelist

	if [ -s "$myblacklist" ] || [ -s "$mywhitelist" ]; then
		echo "> Processing myblacklist and mywhitelist files"
		sed -r 's/^\s*//; s/\s*$//; /^$/d' $myblacklist | sort -u > tmpmybl && mv tmpmybl $myblacklist
		sed -r 's/^\s*//; s/\s*$//; /^$/d' $mywhitelist | sort -u > tmpmywl && mv tmpmywl $mywhitelist
		cat $blacklist | cat $myblacklist - > tmpbl
		cat $whitelist | cat $mywhitelist - | grep -Fvwf $myblacklist > tmpwl
	fi

	echo "> Processing final mphosts and mpdomains files"
	cat $tmphosts | sed $'s/\r$//' | cat tmpbl - | grep -Fvwf tmpwl | sort -u | sed '/^$/d' | awk -v "IP=$supermassiveblackhole" '{sub(/\r$/,""); print IP" "$0}' > $mphosts
	cat $tmpdomains | grep -Fvwf tmpwl | sort -u  > $mpdomains

	echo "> Removing temporary files"
	rm $tmphosts
	rm $tmpdomains
	rm tmpbl
	rm tmpwl

	fileSize=`du -h $mphosts | awk '{print $1}'`
	echo "# Size of $mphosts after formatting: $fileSize"
	fileSize=`du -h $mpdomains | awk '{print $1}'`
	echo "# Size of $mpdomains after formatting: $fileSize"

	# Count how many domains/whitelists were added so it can be displayed to the user
	numberOfAdsBlocked=$(cat $mphosts | wc -l | sed 's/^[ \t]*//')
	echo "# Number of ad domains blocked: approx $numberOfAdsBlocked"

	echo "> Restarting DNS server (dnsmasq)"
	restart_dns

	TIMERSTOP=`date +%s`
	RTMINUTES=$(( $((TIMERSTOP - TIMERSTART)) /60 ))
	RTSECONDS=$(( $((TIMERSTOP - TIMERSTART)) %60 ))
	echo "# Total time: $RTMINUTES:$RTSECONDS minutes"
	echo "# DONE"

else
	echo ">>> ERROR: Network is down. Aborting."
fi

# Give the script permissions to execute:
# chmod +x adbhostgen.sh

# Add the hosts file and extra configuration to DD-WRT's dnsmasq config via Services -> Additional DNSMasq Options
# conf-file=/jffs/dnsmasq/mpdomains
# addn-hosts=/jffs/dnsmasq/mphosts
#
# optional:
# Never forward plain names (without a dot or domain part)
# domain-needed
# Never forward addresses in the non-routed address spaces.
# bogus-priv

# Go to Administration -> Cron (Sets the script to update itself. Choose your own schedule.)
# Build the mphosts file on MON and THU at 6AM
# 0 6 * * 1,4 root /jffs/dnsmasq/adbhostgen.sh
