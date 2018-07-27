#!/bin/sh
# set -euxo pipefail
# File: adbhostgen.sh
#
# Script to generate massive block lists for DD-WRT
#
# AUTHOR: Manish Parashar
#
# https://github.com/m-parashar/adbhostgen
# https://gist.github.com/m-parashar/ee38454c27f7a4f4e4ab28249a834ccc
# https://www.dd-wrt.com/phpBB2/viewtopic.php?t=307533
#
# Thanks: List providers and users.
#
# Installation:
# Give the script permissions to execute:
# chmod +x adbhostgen.sh
#
# Add the hosts file and extra configuration to DD-WRT's dnsmasq config via Services -> Additional DNSMasq Options
# conf-file=/jffs/dnsmasq/mpdomains
# addn-hosts=/jffs/dnsmasq/mphosts
#
# optional:
# Never forward plain names (without a dot or domain part)
# domain-needed
# Never forward addresses in the non-routed address spaces.
# bogus-priv
#
# Log each DNS query as it passes through dnsmasq.
# log-queries
# log-facility=/jffs/dnsmasq/dnsmasq.log
# log-async
#
# Go to Administration -> Cron (Sets the script to update itself. Choose your own schedule.)
# Build the adblock files on MON and THU at 6AM
# 0 6 * * 1,4 root /jffs/dnsmasq/adbhostgen.sh
#

VERSION="20180726a1"

###############################################################################

# define aggressiveness: [ 0 | 1 | 2 | 3 ]
# 0: bare minimum protection from ads and malware
# 1: toned down, tuxedo wearing ad-slaying professional mode [DEFAULT]
# 2: optimum protection
# 3: ramped up, stone cold ad-killing maniac mode
# either change this here or use command line argument
export BLITZ=1

# block Facebook
# f: only block Facebook and Messenger services
# F: block Facebook, Instagram, and WhatsApp
export NOFB=0

# online/offline mode switch
# DO NOT CHANGE; use command line argument instead
export ONLINE=1

# verbosity control
# 0: write to screen & log file
# 1: write to log file only
# exceptions: help, version, errors, warnings
export QUIET=0

# secure communication switch
# if enabled, cURL uses certificates for safe and
# secure TLS/SSL communication
export SECURL=0

# day of week
export DAYOFWEEK=$(date +"%u")

# distribution mode / defaults switch
# if set to 1, ignores myblacklist/mywhitelist files
# DO NOT CHANGE; use command line argument instead
export DISTRIB=0

# where ads go to die
# do not use 0.0.0.0 or 127.0.0.1
export ADHOLEIP="0.1.2.3"

# define dnsmasq directory and path
# needn't be /jffs, could be /opt
# preferably use a USB drive for this
export MPDIR="/jffs/dnsmasq"

# temporary directory
export TMPDIR="/tmp"

# dnsmasq hosts & domain files
export mphosts="${MPDIR}/mphosts"
export mphostspaused="${MPDIR}/mphosts.zzz"
export tmphosts="${TMPDIR}/mphosts.tmp"

# temporary dnsmasq hosts & domain files
export mpdomains="${MPDIR}/mpdomains"
export mpdomainspaused="${MPDIR}/mpdomains.zzz"
export tmpdomains="${TMPDIR}/mpdomains.tmp"

# pause flag
export pauseflag="${MPDIR}/PAUSED"

# blacklist file: a list of blacklisted domains one per line
export blacklist="${MPDIR}/blacklist"

# whitelist file: a list of whitelisted domains one per line
export whitelist="${MPDIR}/whitelist"

# encoded whitelist file: a list of whitelisted domains one per line
export base64wl="${MPDIR}/base64wl"

# user's custom blacklist file: a list of blacklisted domains one per line
export myblacklist="${MPDIR}/myblacklist"

# user's custom whitelist file: a list of whitelisted domains one per line
export mywhitelist="${MPDIR}/mywhitelist"

# log file
export MPLOG="${MPDIR}/mphosts.log"
#[ -s $MPLOG ] && rm -f $MPLOG

# help cron a bit
export SHELL=/bin/sh
export PATH=/bin:/usr/bin:/sbin:/usr/sbin:/jffs/sbin:/jffs/bin:/jffs/usr/sbin:/jffs/usr/bin:/mmc/sbin:/mmc/bin:/mmc/usr/sbin:/mmc/usr/bin:/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:"${MPDIR}"
export LD_LIBRARY_PATH=/lib:/usr/lib:/jffs/lib:/jffs/usr/lib:/jffs/usr/local/lib:/mmc/lib:/mmc/usr/lib:/opt/lib:/opt/usr/lib
export PWD="${MPDIR}"
LC_ALL=C
export LC_ALL

###############################################################################

cd "${MPDIR}"
logger ">>> $(basename "$0") started"

###############################################################################

# cURL certificates and options
if [ -z "$(which curl)" ]; then
	echo ">>> WARNING: cURL not found"
	echo ">>> ERROR: ABORTING"
	exit 1
fi

export CURL_CA_BUNDLE="${MPDIR}/cacert.pem"
alias MPGET="curl -f -s -k"
alias MPGETSSL="curl -f -s -k"
[ $SECURL -eq 1 ] && unalias MPGETSSL && alias MPGETSSL="curl -f -s --capath ${MPDIR} --cacert $CURL_CA_BUNDLE"
alias MPGETMHK="curl -f -s -A "Mozilla/5.0" -e http://forum.xda-developers.com/"
alias SEDSPACE="sed -r 's/^[[:blank:]]*//; s/[[:blank:]]*$//; /^$/d; /^\s*$/d'"
alias GREPFILTER="grep -o '^[^#]*' | grep -vF -e \"::\" -e \";\" -e \"//\" -e \"http\" -e \"https\" -e \"@\" -e \"mailto\" | tr -cd '\000-\177'"

###############################################################################

# echo & log
lognecho ()
{
	[ $QUIET -eq 0 ] && echo "$1"
	echo "$1" >> $MPLOG
}

# print file size
printFileSize ()
{
	lognecho "# Size of $1: `du -h $1 | awk '{print $1}'`"
}

# restart dnsmasq
restart_dnsmasq ()
{
	logger ">>> $(basename "$0") restarting dnsmasq"
	restart_dns &
	logger ">>> $(basename "$0") restarted dnsmasq"
}

# resume protection
protectOn ()
{
	if [ -f $pauseflag ] && { [ -f $mphostspaused ] || [ -f $mpdomainspaused ]; }; then
		lognecho ">>> RESUMING PROTECTION"
		mv $mphostspaused $mphosts
		mv $mpdomainspaused $mpdomains
		rm -f $pauseflag
		restart_dnsmasq
	fi
	logger ">>> $(basename "$0") finished"
	exit 0
}

# pause protection
protectOff ()
{
	lognecho ">>> WARNING: PAUSING PROTECTION"
	[ -f $mphosts ] && mv $mphosts $mphostspaused
	[ -f $mpdomains ] && mv $mpdomains $mpdomainspaused
	echo "" > $mphosts
	echo "" > $mpdomains
	echo "PAUSED" > $pauseflag
	restart_dnsmasq
	lognecho ">>> Type $(basename "$0") --resume to resume protection."
	logger ">>> $(basename "$0") finished"
	exit 0
}

# print help options
printHelp ()
{
	echo ""
	echo "USAGE:"
	printf '\t'; echo "$(basename "$0") [-? | -h | --help] [-v | --version] [-1] [-2] [-b | --bl=<domain.name>] [-w | --wl=<domain.name>] ..."
	echo ""
	echo "OPERATION:"
	printf '\t'; echo -n "[-0]"; printf '\t\t\t\t'; echo "BLITZ=0: safe minimum protection"
	printf '\t'; echo -n "[-1]"; printf '\t\t\t\t'; echo "BLITZ=1: increased protection [DEFAULT]"
	printf '\t'; echo -n "[-2]"; printf '\t\t\t\t'; echo "BLITZ=2: optimum protection"
	printf '\t'; echo -n "[-3]"; printf '\t\t\t\t'; echo "BLITZ=3: unlock maximum protection"
	printf '\t'; echo -n "[-f]"; printf '\t\t\t\t'; echo "Block Facebook and Messenger services"
	printf '\t'; echo -n "[-F]"; printf '\t\t\t\t'; echo "Block Facebook, Messenger, Instagram, WhatsApp"
	printf '\t'; echo -n "[-d | -D]"; printf '\t\t\t'; echo "Ignore myblacklist/mywhitelist entries"
	printf '\t'; echo -n "[-b | --bl=]"; printf '\t'; echo -n "domain.name"; printf '\t'; echo "Add domain.name to myblacklist"
	printf '\t'; echo -n "[-w | --wl=]"; printf '\t'; echo -n "domain.name"; printf '\t'; echo "Add domain.name to mywhitelist"
	printf '\t'; echo -n "[-i | --ip=]"; printf '\t'; echo -n "ip.ad.dr.ss"; printf '\t'; echo "Send ads to this IP, default: $ADHOLEIP"
	printf '\t'; echo -n "[-q | --quiet]"; printf '\t\t\t'; echo "Print outout to log file only"
	printf '\t'; echo -n "[-p | --pause]"; printf '\t\t\t'; echo "Pause protection"
	printf '\t'; echo -n "[-r | --resume]"; printf '\t\t\t'; echo "Resume protection"
	printf '\t'; echo -n "[-s | --secure]"; printf '\t\t\t'; echo "Use cURL CA certs for secure file transfer"
	printf '\t'; echo -n "[-o | --offline]"; printf '\t\t'; echo "Process local lists without downloading"
	printf '\t'; echo -n "[-h | --help]"; printf '\t\t\t'; echo "Display this help screen and exit"
	printf '\t'; echo -n "[-u | --update]"; printf '\t\t\t'; echo "Update $(basename "$0") to the latest version"
	printf '\t'; echo -n "[-v | --version]"; printf '\t\t'; echo "Print $(basename "$0") version and exit"
	echo ""
	echo "EXAMPLES:"
	printf '\t'; echo "$(basename "$0") -s2 --ip=172.31.255.254 --bl=example1.com --wl=example2.com"
	printf '\t'; echo "$(basename "$0") -3Fqs -b example1.com -w example2.com --wl=example3.com"
	echo ""
	logger ">>> $(basename "$0") finished"
	exit 0
}

# update to the latest version
selfUpdate ()
{
	TMPFILE="/tmp/mpupdate"

	lognecho ">>> Checking for updates."

	if ping -q -c 1 -W 1 google.com >/dev/null; then
		MPGETSSL https://raw.githubusercontent.com/m-parashar/adbhostgen/master/$(basename "$0") > $TMPFILE

		if [ 0 -eq $? ]; then
			old_md5=`md5sum $0 | cut -d' ' -f1`
			new_md5=`md5sum $TMPFILE | cut -d' ' -f1`

			if [ "$old_md5" != "$new_md5" ]; then
				NEWVER=`grep -w -m 1 "VERSION" $TMPFILE`
				lognecho ">>> Update available: $NEWVER"
				OLDVER=`grep -w -m 1 "VERSION" $0 | cut -d \" -f2`
				cp $0 $0.$OLDVER
				chmod 755 $TMPFILE
				mv $TMPFILE $0
				lognecho ">>> Updated to the latest version."
			else
				lognecho ">>> No updates available."
			fi
		else
			lognecho ">>> Update failed. Try again."
		fi
		rm -f $TMPFILE
	fi
	logger ">>> $(basename "$0") finished"
	exit 0
}

###############################################################################

# process command line arguments
while getopts "h?v0123fFdDpPqQrRsSoOuUb:w:i:-:" opt; do
	case ${opt} in
		h|\? ) printHelp ;;
		v    ) echo "$VERSION" ; logger ">>> $(basename "$0") finished" ; exit 0 ;;
		0    ) BLITZ=0 ;;
		1    ) BLITZ=1 ;;
		2    ) BLITZ=2 ;;
		3    ) BLITZ=3 ;;
		f    ) NOFB="f" ;;
		F    ) NOFB="F" ;;
		d|D  ) DISTRIB=1 ;;
		q|Q  ) QUIET=1 ;;
		p|P  ) protectOff ;;
		r|R  ) protectOn ;;
		s|S  ) SECURL=1 ;;
		o|O  ) ONLINE=0 ;;
		u|U  ) selfUpdate ;;
		b    ) echo "$OPTARG" >> $myblacklist ;;
		w    ) echo "$OPTARG" >> $mywhitelist ;;
		i    ) ADHOLEIP="$OPTARG" ;;
		-    ) LONG_OPTARG="${OPTARG#*=}"
		case $OPTARG in
			bl=?*   ) ARG_BL="$LONG_OPTARG" ; echo $ARG_BL >> $myblacklist ;;
			bl*     ) echo ">>> ERROR: no arguments for --$OPTARG option" >&2; exit 2 ;;
			wl=?*   ) ARG_WL="$LONG_OPTARG" ; echo $ARG_WL >> $mywhitelist ;;
			wl*     ) echo ">>> ERROR: no arguments for --$OPTARG option" >&2; exit 2 ;;
			ip=?*   ) ARG_IP="$LONG_OPTARG" ; ADHOLEIP=$ARG_IP ;;
			ip*     ) echo ">>> ERROR: no arguments for --$OPTARG option" >&2; exit 2 ;;
			quiet   ) QUIET=1 ;;
			pause   ) protectOff ;;
			resume  ) protectOn ;;
			secure  ) SECURL=1 ;;
			offline ) ONLINE=0 ;;
			help    ) printHelp ;;
			update  ) selfUpdate ;;
			version ) echo "$VERSION" ; logger ">>> $(basename "$0") finished" ; exit 0 ;;
			quiet* | pause* | resume* | secure* | offline* | help* | update* | version* )
					echo ">>> ERROR: no arguments allowed for --$OPTARG option" >&2; exit 2 ;;
			'' )    break ;; # "--" terminates argument processing
			* )     echo ">>> ERROR: unsupported option --$OPTARG" >&2; exit 2 ;;
		esac ;;
  	  \? ) exit 2 ;;  # getopts already reported the illegal option
	esac
done

shift $((OPTIND-1)) # remove parsed options and args from $@ list

###############################################################################

# display banner
TIMERSTART=`date +%s`
lognecho "======================================================"
lognecho "|                adbhostgen for DD-WRT               |"
lognecho "|      https://github.com/m-parashar/adbhostgen      |"
lognecho "|           Copyright 2018 Manish Parashar           |"
lognecho "======================================================"
lognecho "             `date`"
lognecho "# VERSION: $VERSION"

###############################################################################

# force resume if user forgets to turn it back on
if [ -f $pauseflag ] && { [ -f $mphostspaused ] || [ -f $mpdomainspaused ]; }; then
	lognecho "# USER FORGOT TO RESUME PROTECTION AFTER PAUSING"
	protectOn
fi

###############################################################################

# if internet is accessible, download files
if ping -q -c 1 -W 1 google.com &> /dev/null; then

	lognecho "# NETWORK: UP | MODE: ONLINE"
	lognecho "# IP ADDRESS FOR ADS: $ADHOLEIP"
	lognecho "# SECURE [0=NO | 1=YES]: $SECURL"
	lognecho "# BLITZ LEVEL [0|1|2|3]: $BLITZ"

	if [ ! -s cacert.pem ] || { [ "${DAYOFWEEK}" -eq 1 ] || [ "${DAYOFWEEK}" -eq 4 ]; }; then
		lognecho "> Downloading / updating cURL certificates"
		MPGETSSL --remote-name --time-cond cacert.pem https://curl.haxx.se/ca/cacert.pem
	fi

	lognecho "# Creating mpdomains file"
	MPGETSSL https://raw.githubusercontent.com/oznu/dns-zone-blacklist/master/dnsmasq/dnsmasq.blacklist | GREPFILTER | sed 's/0.0.0.0$/'$ADHOLEIP'/' > $tmpdomains
	MPGETSSL https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt | GREPFILTER | sed 's/0.0.0.0$/'$ADHOLEIP'/' >> $tmpdomains
	MPGETSSL -d mimetype=plaintext -d hostformat=dnsmasq https://pgl.yoyo.org/adservers/serverlist.php? | GREPFILTER | sed 's/127.0.0.1$/'$ADHOLEIP'/' >> $tmpdomains

	lognecho "# Creating mphosts file"
	lognecho "> Processing StevenBlack lists"
	MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | GREPFILTER | awk '{print $2}' > $tmphosts

	lognecho "> Processing notracking blocklists"
	MPGETSSL https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

	lognecho "> Processing Disconnect.me lists"
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt | GREPFILTER >> $tmphosts

	lognecho "> Processing quidsup/notrack lists"
	MPGETSSL https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://raw.githubusercontent.com/quidsup/notrack/master/malicious-sites.txt | GREPFILTER >> $tmphosts

	lognecho "> Processing MalwareDomains lists"
	MPGETSSL https://mirror1.malwaredomains.com/files/justdomains | GREPFILTER >> $tmphosts
	MPGETSSL https://mirror1.malwaredomains.com/files/immortal_domains.txt | GREPFILTER >> $tmphosts

	lognecho "> Processing abuse.ch blocklists"
	MPGETSSL https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist | GREPFILTER >> $tmphosts

	lognecho "> Processing Ransomware blocklists"
	MPGETSSL https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://ransomwaretracker.abuse.ch/downloads/CW_C2_DOMBL.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://ransomwaretracker.abuse.ch/downloads/LY_C2_DOMBL.txt | GREPFILTER >> $tmphosts
	MPGETSSL https://ransomwaretracker.abuse.ch/downloads/TC_C2_DOMBL.txt | GREPFILTER >> $tmphosts

	lognecho "> Processing adaway list"
	MPGETSSL https://adaway.org/hosts.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

	if [ $BLITZ -ge 1 ]; then
		lognecho "# Unlocking BLITZ=1 level lists"

		lognecho "> Processing more StevenBlack lists"
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing hosts-file ATS/EXP/GRM lists"
		MPGETSSL https://hosts-file.net/ad_servers.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/exp.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/grm.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing hosts-file HJK/PUP lists"
		MPGETSSL https://hosts-file.net/hjk.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/pup.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing dshield lists"
		MPGETSSL https://www.dshield.org/feeds/suspiciousdomains_High.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://www.dshield.org/feeds/suspiciousdomains_Medium.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://www.dshield.org/feeds/suspiciousdomains_Low.txt | GREPFILTER >> $tmphosts

		lognecho "> Processing pgl.yoyo.org list"
		MPGETSSL -d mimetype=plaintext -d hostformat=unixhosts https://pgl.yoyo.org/adservers/serverlist.php? | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing Securemecca list"
		MPGETSSL https://hostsfile.org/Downloads/hosts.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing cryptomining and porn lists"
		MPGETSSL https://raw.githubusercontent.com/Marfjeh/coinhive-block/master/domains | GREPFILTER >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list | GREPFILTER >> $tmphosts

		lognecho "> Processing Easylist & w3kbl lists"
		MPGETSSL https://v.firebog.net/hosts/AdguardDNS.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Airelle-hrsk.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Airelle-trc.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/BillStearns.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Easylist.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Easyprivacy.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Prigent-Ads.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Prigent-Malware.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Prigent-Phishing.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/Shalla-mal.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://v.firebog.net/hosts/static/w3kbl.txt | GREPFILTER >> $tmphosts
	fi

	if [ $BLITZ -ge 2 ]; then
		lognecho "# Unlocking BLITZ=2 level lists"

		lognecho "> Processing even more StevenBlack lists"
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/KADhosts/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing hosts-file EMD/FSA lists"
		MPGETSSL https://hosts-file.net/emd.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/fsa.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing hosts-file MMT/PHA lists"
		MPGETSSL https://hosts-file.net/mmt.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/pha.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing Cameleon list"
		MPGET http://sysctl.org/cameleon/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing winhelp2002 list"
		MPGET http://winhelp2002.mvps.org/hosts.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing someonewhocares list"
		MPGET http://someonewhocares.org/hosts/zero/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing anudeepND lists"
		MPGETSSL https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/anudeepND/youtubeadsblacklist/master/domainlist.txt | GREPFILTER >> $tmphosts

		lognecho "> Processing CHEF-KOCH lists"
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/WebRTC-tracking/master/WebRTC.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/Spotify-Ad-free/master/Spotifynulled.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/Audio-fingerprint-pages/master/AudioFp.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/Canvas-fingerprinting-pages/master/Canvas.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/CHEF-KOCH/Canvas-Font-Fingerprinting-pages/master/Canvas.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing joewein.de LLC list"
		MPGETSSL https://www.joewein.net/dl/bl/dom-bl-base.txt | GREPFILTER >> $tmphosts

		lognecho "> Processing Windows telemetry lists"
		MPGETSSL https://raw.githubusercontent.com/tyzbit/hosts/master/data/tyzbit/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing smart TV blocklists"
		MPGETSSL https://v.firebog.net/hosts/static/SamsungSmart.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt | GREPFILTER >> $tmphosts

		lognecho "> Processing a few more blocklists"
		MPGETSSL https://raw.githubusercontent.com/vokins/yhosts/master/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/HenningVanRaumle/pihole-ytadblock/master/ytadblock.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt | GREPFILTER >> $tmphosts
		MPGETSSL https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt | GREPFILTER >> $tmphosts
	fi

	if [ $BLITZ -ge 3 ]; then
		lognecho "# Unlocking BLITZ=3 level lists"

		lognecho "> Processing hosts-file PSH/PUP/WRZ lists"
		MPGETSSL https://hosts-file.net/psh.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
		MPGETSSL https://hosts-file.net/wrz.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing Mahakala list"
		MPGETMHK http://adblock.mahakala.is/hosts | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing HostsFile.mine.nu list"
		MPGETSSL https://hostsfile.mine.nu/hosts0.txt | GREPFILTER | awk '{print $2}' >> $tmphosts

		lognecho "> Processing Kowabit list"
		MPGETSSL https://v.firebog.net/hosts/Kowabit.txt | GREPFILTER >> $tmphosts

		lognecho "> Processing ADZHOSTS list"
		MPGETSSL https://adzhosts.hizo.fr/hosts/adzhosts-android.txt | GREPFILTER | awk '{print $2}' >> $tmphosts
	fi

	if [ $NOFB = "f" ]; then
		lognecho "> Blocking Facebook and Messenger"
		MPGETSSL https://raw.githubusercontent.com/m-parashar/adbhostgen/master/blacklists/facebookonly.block >> $tmphosts
	fi

	if [ $NOFB = "F" ]; then
		lognecho "> Blocking Facebook, Messenger, Instagram, WhatsApp"
		MPGETSSL https://raw.githubusercontent.com/m-parashar/adbhostgen/master/blacklists/facebookall.block >> $tmphosts
	fi

	lognecho "> Updating official blacklist/whitelist files"
	MPGETSSL https://raw.githubusercontent.com/m-parashar/adbhostgen/master/blacklists/blacklist | GREPFILTER > $blacklist
	MPGETSSL https://raw.githubusercontent.com/m-parashar/adbhostgen/master/whitelists/whitelist | GREPFILTER > $whitelist
	MPGETSSL https://raw.githubusercontent.com/m-parashar/adbhostgen/master/whitelists/fruitydomains > $base64wl
	LC_ALL=C uudecode $base64wl && cat applewhitelist >> $whitelist && rm applewhitelist && rm $base64wl

else
	lognecho "# NETWORK: DOWN | MODE: OFFLINE"
	logger ">>> $(basename "$0") finished"
	exit 0
fi

if [ $ONLINE -eq 0 ]; then
	lognecho "# NETWORK: DOWN | MODE: OFFLINE"
	lognecho "# OFFLINE PROCESSING"
	[ -s $mphosts ] && cat $mphosts | awk '{print $2}' > $tmphosts
	[ -s $mpdomains ] && cp $mpdomains $tmpdomains
	restart_dnsmasq
	logger ">>> $(basename "$0") finished"
	exit 0
fi

###############################################################################

# calculate and print file sizes
printFileSize $tmphosts
printFileSize $tmpdomains

# remove duplicates and extra whitespace, sort alphabetically
lognecho "> Processing blacklist/whitelist files"
LC_ALL=C cat $blacklist | sed -r 's/^[[:blank:]]*//; s/[[:blank:]]*$//; /^$/d; /^\s*$/d' | sort | uniq > tmpbl && cp tmpbl $blacklist
LC_ALL=C cat $whitelist | sed -r 's/^[[:blank:]]*//; s/[[:blank:]]*$//; /^$/d; /^\s*$/d' | sort | uniq > tmpwl && cp tmpwl $whitelist

# if not building for distribution, process myblacklist and mywhitelist files
# remove duplicates and extra whitespace, sort alphabetically
# and allow users' myblacklist precedence over defaults
if [ $DISTRIB -eq 0 ] && { [ -s "$myblacklist" ] || [ -s "$mywhitelist" ]; }; then
	lognecho "> Processing myblacklist/mywhitelist files"
	LC_ALL=C cat $myblacklist | sed -r 's/^[[:blank:]]*//; s/[[:blank:]]*$//; /^$/d; /^\s*$/d' | sort | uniq > tmpmybl && mv tmpmybl $myblacklist
	LC_ALL=C cat $mywhitelist | sed -r 's/^[[:blank:]]*//; s/[[:blank:]]*$//; /^$/d; /^\s*$/d' | sort | uniq > tmpmywl && mv tmpmywl $mywhitelist
	cat $blacklist | cat $myblacklist - > tmpbl
	cat $whitelist | cat $mywhitelist - | grep -Fvwf $myblacklist > tmpwl
fi

# trim leading and trailig whitespace, delete all blank lines including the ones with whitespace
# remove non-printable non-ASCII characters because DD-WRT dnsmasq throws "bad name at line n" errors
# merge blacklists with other lists and remove whitelist entries from the stream
lognecho "> Processing final mphosts/mpdomains files"
LC_ALL=C cat $tmphosts | sed -r 's/^[[:blank:]]*//; s/[[:blank:]]*$//; /^$/d; /^\s*$/d' | cat tmpbl - | grep -Fvwf tmpwl | sort | uniq | awk -v "IP=$ADHOLEIP" '{sub(/\r$/,""); print IP" "$0}' > $mphosts
LC_ALL=C cat $tmpdomains | sed -r 's/^[[:blank:]]*//; s/[[:blank:]]*$//; /^$/d; /^\s*$/d' | grep -Fvwf tmpwl | sort | uniq > $mpdomains

lognecho "> Removing temporary files"
rm -f $tmphosts
rm -f $tmpdomains
rm -f tmpbl
rm -f tmpwl

# calculate and print file sizes
printFileSize $mphosts
printFileSize $mpdomains

# Count how many domains/whitelists were added so it can be displayed to the user
numHostsBlocked=$(cat $mphosts | wc -l | sed 's/^[ \t]*//')
lognecho "# Number of ad hosts blocked: approx $numHostsBlocked"
numDomainsBlocked=$(cat $mpdomains | wc -l | sed 's/^[ \t]*//')
lognecho "# Number of ad domains blocked: approx $numDomainsBlocked"

lognecho "> Restarting DNS server (dnsmasq)"
restart_dnsmasq

TIMERSTOP=`date +%s`
RTMINUTES=$(( $((TIMERSTOP - TIMERSTART)) /60 ))
RTSECONDS=$(( $((TIMERSTOP - TIMERSTART)) %60 ))
lognecho "# Total time: $RTMINUTES:$RTSECONDS minutes"
lognecho "# DONE"
logger ">>> $(basename "$0") finished"
exit 0
# FIN
