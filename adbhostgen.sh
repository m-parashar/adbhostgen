#!/bin/sh
# File: adbhostgen.sh
#
# Script to generate a MEGA hosts file for DD-WRT
# for use with dnsmasq's addn-hosts configuration
#
# https://github.com/m-parashar/adbhostgen
# https://gist.github.com/m-parashar/ee38454c27f7a4f4e4ab28249a834ccc
# https://www.dd-wrt.com/phpBB2/viewtopic.php?t=307533
#
# thanks1 : https://gist.github.com/chrisvella/5f3a18f1e442153cd685
# thanks2 : https://gist.github.com/p-hash/ff8e5b85f3be236010c8cefe8b3e97c0
# thanks3 : Arthur Borsboom https://github.com/arthurborsboom
#
# @Manish Parashar
# Last updated: 2018/02/22

VERSION="20180222"

# Address to send ads to. This could possibily be removed, but may be useful for debugging purposes?
destinationIP="0.0.0.0"

# Define dnsmasq directory and path. Required for cron.
MPDIR='/jffs/dnsmasq'
TMPDIR='/tmp'

mphosts="${MPDIR}/mphosts"
#bkphosts="${MPDIR}/mphosts.bkp"
tmphosts="${TMPDIR}/mphosts.tmp"

# dnsmasq domain file: auto download
mpdomains="${MPDIR}/mpdomains"
tmpdomains="${TMPDIR}/mpdomains.tmp"

# whitelist file: a list of whitelisted domains one per line
whitelist="${MPDIR}/whitelist"

# blacklist file: hosts to be added explicitly
blacklist="${MPDIR}/blacklist"

# define aggressiveness: [ 0 | 1 ]
BLITZ=0

if [ "$SELF_LOGGING" != "1" ]; then
    # The parent process will enter this branch and set up logging

    # Create a named piped for logging the child's output
    PIPE=tmp.fifo
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

	echo "Network up. Generating the hosts file now..."

	if [ ! -e cacert.pem ] || [ $(date +%A) = "Monday" ]; then
		echo "Downloading / updating cURL cacert for secure communication..."
		curl -s --cacert cacert.pem --remote-name --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem || curl -s -k --remote-name --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem
	fi

	if [ ! -e $whitelist ] || [ ! -e $blacklist ]; then
		echo "Whitelist and Blacklist files not found. Downloading latest defaults..."
		curl -s --cacert cacert.pem https://raw.githubusercontent.com/m-parashar/adbhostgen/master/whitelist > $whitelist
		curl -s --cacert cacert.pem https://raw.githubusercontent.com/m-parashar/adbhostgen/master/blacklist > $blacklist
	fi

	if [ $BLITZ -eq 1 ]; then
		echo "BLITZ mode ON."
		
	else
		echo "BLITZ mode OFF."
	fi

	echo "StevenBlack list"
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort > $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/StevenBlack/hosts/master/data/tyzbit/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/StevenBlack/hosts/master/data/SpotifyAds/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/oznu/dns-zone-blacklist/master/dnsmasq/dnsmasq.blacklist | grep -v "#" > $tmpdomains

	echo "notracking list"
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt | grep -v "#" >> $tmpdomains

	echo "Cameleon list"
	curl -s http://sysctl.org/cameleon/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts

	echo "hosts-file ad_servers list"
	curl -s --cacert cacert.pem https://hosts-file.net/ad_servers.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts

	echo "Disconnect.me list"
	curl -s --cacert cacert.pem https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt | grep -v "#" >> $tmphosts

	echo "quidsup/notrack list"
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/quidsup/notrack/master/malicious-sites.txt | grep -v "#" >> $tmphosts
	
	echo "MalwareDomains list"
	curl -s --cacert cacert.pem https://mirror1.malwaredomains.com/files/justdomains >> $tmphosts
	curl -s --cacert cacert.pem https://mirror1.malwaredomains.com/files/immortal_domains.txt | grep -v "#" >> $tmphosts

	echo "Securemecca list"
	curl -s --cacert cacert.pem https://hostsfile.org/Downloads/hosts.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts

	echo "abuse.ch blocklist"
	curl -s --cacert cacert.pem https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | grep -v "#" >> $tmphosts

	echo "adaway list"
	curl -s --cacert cacert.pem https://adaway.org/hosts.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts

	echo "Easylist & others"
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/AdguardDNS.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Airelle-hrsk.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Airelle-trc.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/BillStearns.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Easylist.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Easyprivacy.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Kowabit.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Prigent-Ads.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Prigent-Malware.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Prigent-Phishing.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Shalla-mal.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/static/SamsungSmart.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/static/w3kbl.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://www.dshield.org/feeds/suspiciousdomains_High.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://www.dshield.org/feeds/suspiciousdomains_Low.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://www.dshield.org/feeds/suspiciousdomains_Medium.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/tyzbit/hosts/master/data/tyzbit/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt | grep -v "#" >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win10/spy.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list | grep -v "#" >> $tmphosts
	
	if [ $BLITZ -eq 1 ]; then
		echo "winhelp2002 list"
		curl -s http://winhelp2002.mvps.org/hosts.txt | grep -v "#" | grep -v "127.0.0.1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | sort >> $tmphosts

		echo "Yoyo list"
		curl -s --cacert cacert.pem -d mimetype=plaintext -d hostformat=unixhosts https://pgl.yoyo.org/adservers/serverlist.php? | sort >> $tmphosts

		echo "HostsFile.mine.nu list"
		curl -s --cacert cacert.pem https://hostsfile.mine.nu/hosts0.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts

		echo "Mother of All Ad Blocks list"
		curl -s --cacert cacert.pem -A 'Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0' -e http://forum.xda-developers.com/ https://adblock.mahakala.is/ | grep -v "#" | awk '{print $2}' | sort >> $tmphosts

		echo "someonewhocares list"
		curl -s http://someonewhocares.org/hosts/zero/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts

		echo "ADZHOSTS list"
		curl -s --cacert cacert.pem https://pilotfiber.dl.sourceforge.net/project/adzhosts/HOSTS.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts

		echo "mat1th list"
		curl -s --cacert cacert.pem https://raw.githubusercontent.com/mat1th/Dns-add-block/master/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tmphosts
	fi

	# Remove entries from the whitelist file if it exists at the root of the current user's home folder
	echo "Processing whitelist and blacklist files..."
	sed -r 's/^\s*//; s/\s*$//; /^$/d' $blacklist | sort -u > tmpbl && mv tmpbl $blacklist
	sed -r 's/^\s*//; s/\s*$//; /^$/d' $whitelist | sort -u > tmpwl && mv tmpwl $whitelist

	fileSize=`du -h $tmphosts | awk '{print $1}'`
	echo "Size of $tmphosts before formatting: $fileSize"
	fileSize=`du -h $tmpdomains | awk '{print $1}'`
	echo "Size of $tmpdomains before formatting: $fileSize"

	echo "Removing duplicates and formatting the list of domains..."
	#[ -f "$mphosts" ] && cp $mphosts $bkphosts
	cat $tmphosts | sed $'s/\r$//' | cat "$blacklist" - | grep -F -v -f $whitelist | sort -u | sed '/^$/d' | awk -v "IP=$destinationIP" '{sub(/\r$/,""); print IP" "$0}' > $mphosts
	cat $tmpdomains | grep -F -v -f $whitelist | sort -u  > $mpdomains

	echo "Removing temporary lists..."
	rm $tmphosts
	rm $tmpdomains

	fileSize=`du -h $mphosts | awk '{print $1}'`
	echo "Size of $mphosts after formatting: $fileSize"
	fileSize=`du -h $mpdomains | awk '{print $1}'`
	echo "Size of $mpdomains after formatting: $fileSize"

	# Count how many domains/whitelists were added so it can be displayed to the user
	numberOfAdsBlocked=$(cat $mphosts | wc -l | sed 's/^[ \t]*//')
	echo "$numberOfAdsBlocked ad domains blocked."

	echo "Restarting DNS server (dnsmasq)..."
	restart_dns

else
	echo "Network is down. Aborting."
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
