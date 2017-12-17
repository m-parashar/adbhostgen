#!/bin/sh
# File: adbhostgen.sh
# Script to generate a MEGA hosts file for DD-WRT
# for use with dnsmasq's addn-hosts configuration
# https://github.com/m-parashar/adbhostgen
# https://gist.github.com/m-parashar/ee38454c27f7a4f4e4ab28249a834ccc
#
# thanks1 : https://gist.github.com/chrisvella/5f3a18f1e442153cd685
# thanks2 : https://gist.github.com/p-hash/ff8e5b85f3be236010c8cefe8b3e97c0
#
# @Manish Parashar
# Last updated: 2017/12/18

# Address to send ads to. This could possibily be removed, but may be useful for debugging purposes?
destinationIP="0.0.0.0"

# Define dnsmasq directory and path. Required for cron.
MPDIR='/jffs/dnsmasq'

outlist="${MPDIR}/mphosts"
bkplist="${MPDIR}/mphosts.1"
tempoutlist="$outlist.tmp"

# whitelist file: a list of whitelisted domains one per line
whitelist="${MPDIR}/whitelist"

# blacklist file: hosts to be added explicitly
blacklist="${MPDIR}/blacklist"

# dnsmasq domain file: auto download
mpdomains="${MPDIR}/mpdomains"
tempmpdlist="$mpdomains.tmp"

# define aggressiveness: [ 0 | 1 ]
BLITZ=0

if ping -q -c 1 -W 1 google.com >/dev/null; then

	echo "Network up. Generating the hosts file now..."

	if [ ! -e cacert.pem ] || [ $(date +%A) = "Monday" ]; then
		echo "Downloading cURL cacert for secure communication."
		curl -s --cacert cacert.pem --remote-name --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem || curl -s -k --remote-name --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem
	fi

	if [ $BLITZ -eq 1 ]; then
		echo "BLITZ mode ON."
		
	else
		echo "BLITZ mode OFF."
	fi

	echo "StevenBlack list"
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort > $tempoutlist

	echo "notracking list"
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt | grep -v "#" > $tempmpdlist

	echo "Cameleon list"
	curl -s http://sysctl.org/cameleon/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "hosts-file ad/tracking list"
	curl -s --cacert cacert.pem https://hosts-file.net/ad_servers.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "Disconnect.me list"
	curl -s --cacert cacert.pem https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt | grep -v "#" >> $tempoutlist

	echo "quidsup/notrack list"
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/quidsup/notrack/master/malicious-sites.txt | grep -v "#" >> $tempoutlist
	
	echo "MalwareDomains list"
	curl -s --cacert cacert.pem https://mirror1.malwaredomains.com/files/justdomains >> $tempoutlist
	curl -s --cacert cacert.pem https://mirror1.malwaredomains.com/files/immortal_domains.txt | grep -v "#" >> $tempoutlist

	echo "malwaredomainlist list"
	curl -s --cacert cacert.pem https://www.malwaredomainlist.com/hostslist/hosts.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $3}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "abuse.ch blocklist"
	curl -s --cacert cacert.pem https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | grep -v "#" >> $tempoutlist

	echo "adaway list"
	curl -s --cacert cacert.pem https://adaway.org/hosts.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "Easylist & others"
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Easylist.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/AdguardDNS.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/BillStearns.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/static/w3kbl.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Airelle-trc.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Airelle-hrsk.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Shalla-mal.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Easyprivacy.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Prigent-Ads.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Prigent-Malware.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://v.firebog.net/hosts/Prigent-Phishing.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://www.joewein.net/dl/bl/dom-bl-base.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://www.dshield.org/feeds/suspiciousdomains_Low.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | grep -v "#" >> $tempoutlist
	curl -s --cacert cacert.pem https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list | grep -v "#" >> $tempoutlist

	if [ $BLITZ -eq 1 ]; then
		echo "winhelp2002 list"
		curl -s http://winhelp2002.mvps.org/hosts.txt | grep -v "#" | grep -v "127.0.0.1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | sort >> $tempoutlist

		echo "Yoyo list"
		curl -s --cacert cacert.pem -d mimetype=plaintext -d hostformat=unixhosts https://pgl.yoyo.org/adservers/serverlist.php? | sort >> $tempoutlist

		echo "Securemecca list"
		curl -s --cacert cacert.pem https://hostsfile.org/Downloads/hosts.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

		echo "Mother of All Ad Blocks list"
		curl -s --cacert cacert.pem -A 'Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0' -e http://forum.xda-developers.com/ https://adblock.mahakala.is/ | grep -v "#" | awk '{print $2}' | sort >> $tempoutlist

		echo "someonewhocares list"
		curl -s http://someonewhocares.org/hosts/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

		echo "ADZHOSTS list"
		curl -s --cacert cacert.pem https://pilotfiber.dl.sourceforge.net/project/adzhosts/HOSTS.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

		echo "mat1th list"
		curl -s --cacert cacert.pem https://raw.githubusercontent.com/mat1th/Dns-add-block/master/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	fi

	# Remove entries from the whitelist file if it exists at the root of the current user's home folder
	echo "Removing duplicates and formatting the list of domains..."
	sed -r 's/^\s*//; s/\s*$//; /^$/d' $blacklist | sort -u > tmpch && mv tmpch $blacklist
	sed -r 's/^\s*//; s/\s*$//; /^$/d' $whitelist | sort -u > tmpwl && mv tmpwl $whitelist
	[ -f "$outlist" ] && cp $outlist $bkplist
	cat $tempoutlist | sed $'s/\r$//' | cat "$blacklist" - | grep -F -v -f $whitelist | sort -u | sed '/^$/d' | awk -v "IP=$destinationIP" '{sub(/\r$/,""); print IP" "$0}' > $outlist
	cat $tempmpdlist | grep -F -v -f $whitelist | sort -u  > $mpdomains

	# Removes the temporary list.
	rm $tempoutlist
	rm $tempmpdlist

	# Count how many domains/whitelists were added so it can be displayed to the user
	numberOfAdsBlocked=$(cat $outlist | wc -l | sed 's/^[ \t]*//')
	echo "$numberOfAdsBlocked ad domains blocked."

else
	echo "Network is down. Aborting."
fi

# Give the script permissions to execute:
# chmod +x adbhostgen.sh

# Add the hosts file and extra configuration to DD-WRT's dnsmasq config via Services -> Additional DNSMasq Options
# conf-file=/jffs/dnsmasq/mpdomains
# addn-hosts=/jffs/dnsmasq/mphosts
# Never forward plain names (without a dot or domain part)
# domain-needed
# Never forward addresses in the non-routed address spaces.
# bogus-priv

# For debugging purposes, log each DNS query as it passes through dnsmasq. Remove this once you have confirmed it is working.
# log-queries
# log-facility=/jffs/dnsmasq/adblocking.log
# This allows it to continue functioning without being blocked by syslog, and allows syslog to use dnsmasq for DNS queries without risking deadlock
# log-async

# Go to Administration -> Cron (Sets the script to update itself. Choose your own schedule.)
# Build the mphosts file on MON and THU at 6AM
# 0 6 * * 1,4 root /jffs/dnsmasq/adbhostgen.sh

# Add another custom command:
# 30 6 * * 1,4 root restart_dns
# ~OR~
# stopservice dnsmasq; startservice dnsmasq
# ~OR~
# killall -1 dnsmasq
# ~OR~
# Have the router reboot sometime after the script has been downloaded.

