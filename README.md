# Ad-blocking on DD-WRT

VERSION: 20180209 [YYYYMMDD]

System: Netgear R8500

Firmware: DD-WRT v3.0-r34800M kongac (02/07/18)

Additional configuration: Preferably a USB pendrive partitioned and formatted as swap and /jffs.

![jffs](https://i.imgur.com/bDJBxd8.png)
![usb](https://i.imgur.com/3c5kkTM.png)

Solution: hosts file & dnsmasq

7z download link: https://github.com/m-parashar/adbhostgen/blob/master/adbhostgen.7z?raw=true

Github: https://github.com/m-parashar/adbhostgen - includes downloadable mpdomains & mphosts, and cacert.

Gist: https://gist.github.com/m-parashar/ee38454c27f7a4f4e4ab28249a834ccc

Instructions: 

1. Copy adbhostgen.sh to /jffs/dnsmasq directory. chmod +x it.

2. OPTIONAL: Edit adbhostgen.sh to set BLITZ mode to 1, if you want an aggressive hosts file. By default BLITZ is set to 0.

3. Copy file "whitelist" to /jffs/dnsmasq and add the domains you do not want blocked.

4. Copy file "blacklist" to /jffs/dnsmasq and add the domains you want blocked.

5. Copy "cacert.pem" [See github link] to /jffs/dnsmasq.

6. Enable DNSMasq and local DNS for LAN and WAN

7. Enter this into the additional options field

    ```
    conf-file=/jffs/dnsmasq/mpdomains
    addn-hosts=/jffs/dnsmasq/mphosts
    ```
Enter additional options for dnsmasq if required, for example:

    ```
    domain-needed
    bogus-priv
    ```
    
![dnsmasq](https://i.imgur.com/ez7yLM4.png)

8. Under Administration -> Cron, enter this or choose your own schedule: 

    ```
    0 6 * * 1,4 root /jffs/dnsmasq/adbhostgen.sh
    ```

![cron](https://i.imgur.com/Y7RAEVk.png)

9. Reboot 

Should work on R7000, R8000 and other >128MB RAM routers too. Any feedback is welcome. 

SIZE:

mpdomains: ~2 MiB

BLITZ=0 mphosts: ~9 MiB

Status: 

![log](https://i.imgur.com/Sl5tBWu.png)

![sysstat](https://i.imgur.com/dS2Zhru.png)
