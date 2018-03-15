# Ad-blocking on DD-WRT
---------------------
Script to generate a MEGA hosts file for DD-WRT

https://github.com/m-parashar/adbhostgen
Copyright 2018 Manish Parashar

Developed and tested on: NETGEAR R8500 / DD-WRT v3.0-r35030M kongac 
Hardware requirements: Minimum 4GB USB drive. 
Partitioned, formatted, and mounted as /jffs (1-2GB), swap (256-512MB), and optionally /opt (1-2GB) 

NOTE: DO NOT try to run this script on your internal jffs. 

Software requirements: DD-WRT (preferably latest), cURL 

DOWNLOAD: https://github.com/m-parashar/adbhostgen/releases

Installation:
-------------

1a. Download installer.sh and make it executable (chmod +x), then run it in /tmp or /jffs.
    It will automatically create /jffs/dnsmasq and extract required files into it. OR

1b. Download and extract adbhostgen.7z or adbhostgen.tar.gz into /jffs/dnsmasq directory.

2. Run adbhostgen.sh in /jffs/dnsmasq

Settings:
---------

1. Disable internal flash (JFFS2) if you already have a USB drive mounted as /jffs.

![usb](https://i.imgur.com/3c5kkTM.png)
![jffs](https://i.imgur.com/bDJBxd8.png)

2. Enable DNSMasq and local DNS for LAN and WAN. Add these lines under the additional options section.

    ```
    conf-file=/jffs/dnsmasq/mpdomains
    addn-hosts=/jffs/dnsmasq/mphosts
    ```

![dnsmasq](https://i.imgur.com/ez7yLM4.png)

3. Enter additional options for dnsmasq if required, for example:

    domain-needed
    bogus-priv

4. Under Administration -> Cron, enter this or choose your own schedule:

    ```
    0 6 * * 1,4 root /jffs/dnsmasq/adbhostgen.sh
    ```

![cron](https://i.imgur.com/Y7RAEVk.png)

5. Reboot

Usage:
------

Add your blacklist or whitelist domains to myblacklist and mywhitelist files respectively.
Do not save anything in blacklist or whitelist files as they will be overwritten every
time the script is executed.

![cmdline](https://i.imgur.com/xnvvT4m.png)

FOR DETAILS AND SCREENSHOTS: https://www.dd-wrt.com/phpBB2/viewtopic.php?t=307533

--

Should work on R7000, R8000 and other >128MB RAM routers too. Any feedback is welcome. 

| mode            | size    | number of domains blocked |
|-----------------|---------|---------------------------|
| BLITZ=0 mphosts | 2.7 MB  | ~103332                   |
| BLITZ=0 mphosts | 9.8 MB  | ~355660                   |
| BLITZ=0 mphosts | 25.6 MB | ~913386                   |
| BLITZ=0 mphosts | 34.7 MB | ~1241313                  |

| mode     | processing time (minutes) |
|----------|---------------------------|
| BLITZ=0  |  1:45                     |
| BLITZ=0  |  3:38                     |
| BLITZ=0  |  6:32                     |
| BLITZ=0  | 10:16                     |

Status: 

![log](https://i.imgur.com/VBaf3If.png)

![sysstat](https://i.imgur.com/dS2Zhru.png)
