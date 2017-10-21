#!/bin/sh
# Modified Pi-hole script to generate a hosts file for DD-WRT (tested on Netgear R8500)
# for use with dnsmasq's addn-hosts configuration
# ref0 : https://github.com/jacobsalmela/pi-hole/blob/master/gravity-adv.sh
# ref1 : https://gist.github.com/chrisvella/5f3a18f1e442153cd685
# ref2 : https://gist.github.com/p-hash/ff8e5b85f3be236010c8cefe8b3e97c0
# @Manish Parashar
# Last updated: 2017/05/13

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

if ping -q -c 1 -W 1 google.com >/dev/null; then

	echo "Network up. Generating the hosts file now..."

	echo "01. Mother of All Ad Blocks list"
	curl -s -A 'Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0' -e http://forum.xda-developers.com/ http://adblock.mahakala.is/ | grep -v "#" | awk '{print $2}' | sort > $tempoutlist

	echo "02. winhelp2002 ad list"
	curl -s http://winhelp2002.mvps.org/hosts.txt | grep -v "#" | grep -v "127.0.0.1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | sort >> $tempoutlist

	echo "03. adaway ad list"
	curl -s -k https://adaway.org/hosts.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "04. Yoyo ad list"
	curl -s -d mimetype=plaintext -d hostformat=unixhosts http://pgl.yoyo.org/adservers/serverlist.php? | sort >> $tempoutlist

	echo "05. malwaredomains.lehigh.edu list"
	curl -s http://malwaredomains.lehigh.edu/files/justdomains >> $tempoutlist
	curl -s http://malwaredomains.lehigh.edu/files/immortal_domains.txt | grep -v "#" >> $tempoutlist

	echo "06. Disconnect.me list"
	curl -s -k https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt | grep -v "#" >> $tempoutlist
	curl -s -k https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt | grep -v "#" >> $tempoutlist
	curl -s -k https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt | grep -v "#" >> $tempoutlist
	curl -s -k https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt | grep -v "#" >> $tempoutlist

	echo "07. malwaredomainlist ad list"
	curl -s http://www.malwaredomainlist.com/hostslist/hosts.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $3}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "08. StevenBlack ad list"
	curl -s -k https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "09. abuse.ch ZeuS domain blocklist"
	curl -s -k https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist | grep -v "#" >> $tempoutlist

	echo "10.1 hosts-file ad/tracking list"
	curl -s -k https://hosts-file.net/ad_servers.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	#echo "10.2 hosts-file malware list"
	#curl -s -k https://hosts-file.net/emd.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	#echo "10.3 hosts-file exploit list"
	#curl -s -k https://hosts-file.net/exp.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	#echo "10.4 hosts-file fraud list"
	#curl -s -k https://hosts-file.net/fsa.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	#echo "10.5 hosts-file spam list"
	#curl -s -k https://hosts-file.net/grm.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	#echo "10.6 hosts-file hijack list"
	#curl -s -k https://hosts-file.net/hjk.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	#echo "10.7 hosts-file phishing list"
	#curl -s -k https://hosts-file.net/psh.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	#echo "10.8 hosts-file misleading marketing list"
	#curl -s -k https://hosts-file.net/mmt.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist
	#echo "10.9 hosts-file latest partial list"
	#curl -s -k https://hosts-file.net/hphosts-partial.txt | grep -v "#" | grep -v "::1" | sed '/^$/d' | sed 's/\ /\\ /g' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "11. someonewhocares ad list"
	curl -s http://someonewhocares.org/hosts/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "12. hostsfile.mine.nu ad list"
	curl -s http://hostsfile.mine.nu/Hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "13. Cameleon ad list"
	curl -s http://sysctl.org/cameleon/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "14. Securemecca list"
	curl -s http://securemecca.com/Downloads/hosts.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "15. ADZHOSTS list"
	curl -s http://pilotfiber.dl.sourceforge.net/project/adzhosts/HOSTS.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "16. mat1th list"
	curl -s -k https://raw.githubusercontent.com/mat1th/Dns-add-block/master/hosts | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "17. notracking list"
	curl -s -k https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt | grep -v "#" | sed '/^$/d' | sed 's/\ /\\ /g' | grep -v '^\\' | grep -v '\\$' | awk '{print $2}' | grep -v '^\\' | grep -v '\\$' | sort >> $tempoutlist

	echo "18. quidsup/notrack list"
	curl -s -k https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt | grep -v "#" >> $tempoutlist

	# Remove entries from the whitelist file if it exists at the root of the current user's home folder
	echo "Removing duplicates and formatting the list of domains..."
	# Removed the uniq command, using sort -u. Removes the dependency on uniq, which is not available on the router by default or via opkg.
	# Added a rough way to exclude domains from the list. If you have a number of domains to whitelist, a better solution could be explored.
	#	cat $tempoutlist | sed $'s/\r$//' | sed '/thisisiafakedomain123\.com/d;/www\.anotherfakedomain123\.com/d' | sort -u | sed '/^$/d' | awk -v "IP=$destinationIP" '{sub(/\r$/,""); print IP" "$0}' > $outlist

	sed -r 's/^\s*//; s/\s*$//; /^$/d' $blacklist | sort -u > tmpch && mv tmpch $blacklist
	sed -r 's/^\s*//; s/\s*$//; /^$/d' $whitelist | sort -u > tmpwl && mv tmpwl $whitelist
	[ -f "$outlist" ] && cp $outlist $bkplist
	cat $tempoutlist | sed $'s/\r$//' | cat "$blacklist" - | grep -F -v -f $whitelist | sort -u | sed '/^$/d' | awk -v "IP=$destinationIP" '{sub(/\r$/,""); print IP" "$0}' > $outlist

	# Removes the temporary list.
	rm $tempoutlist

	# Count how many domains/whitelists were added so it can be displayed to the user
	numberOfAdsBlocked=$(cat $outlist | wc -l | sed 's/^[ \t]*//')
	echo "$numberOfAdsBlocked ad domains blocked."

else
	echo "Network is down. Aborting."
fi

# Give the script permissions to execute:
# chmod +x adbhostgen.sh

# Add the hosts file and extra configuration to DD-WRT's dnsmasq config via Services -> Additional DNSMasq Options
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
