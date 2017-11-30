# Ad-blocking on Netgear R8500 

System: Netgear R8500 

Firmware: DD-WRT v3.0-r33770M kongac (11/15/17) 

Additional configuration: OpenVPN client and an 8 GiB pendrive partitioned and formatted as swap, /jffs, and /opt running Kong's optware. 

Background: Needed a more elegant and cleaner setup than dealing with the nuances of OpenVPN and Privoxy enabled on the same router. Repurposing RPi3 had something to do with it, too. 

Solution: hosts file & dnsmasq 

Github: https://github.com/m-parashar/adbhostgen - includes downloadable mpdomains & mphosts. 
Gist: https://gist.github.com/m-parashar/ee38454c27f7a4f4e4ab28249a834ccc 

Instructions: 

1. Copy/create adbhostgen.sh / adbhostgensec.sh in /jffs/dnsmasq directory. chmod +x it. 

2. Create/download the file "whitelist" without quotes in /jffs/dnsmasq and populate it with the domains you do not want blocked. ̶E̶n̶s̶u̶r̶e̶ ̶t̶h̶e̶r̶e̶'̶s̶ ̶n̶o̶ ̶t̶r̶a̶i̶l̶i̶n̶g̶ ̶n̶e̶w̶l̶i̶n̶e̶/̶c̶r̶.̶ [rev25] 

3. Create/download file "blacklist" and populate it with the domains you want to block. [rev30] 

4. Execute adbhostgen.sh in /jffs/dnsmasq to generate the hosts file. By default the hosts file is quite aggressive and approx 10 MiB in size, which is manageable enough for Netgear R8500. Comment out the hosts repos as you see fit. 

5. Enable DNSMasq and local DNS for LAN and WAN 

6. Enter this into the additional options field [rev33] 

    ```
    conf-file=/jffs/dnsmasq/mpdomains 
    addn-hosts=/jffs/dnsmasq/mphosts 
    domain-needed 
    bogus-priv
    ```

![dnsmasq](https://i.imgur.com/Qn65vV5.png)

7. Under Administration -> Cron, enter this or choose your own schedule: 

    ```
    0 6 * * 1,4 root /jffs/dnsmasq/adbhostgen.sh 
    30 6 * * 1,4 root restart_dns
    ```

![cron](http://i.imgur.com/c98Hd9u.png)

8. Reboot 

Should work on R7000, R8000 and other >128MB RAM routers too. Any feedback is welcome. 

SIZE: 
mpdomains: ~2MiB 
mphosts: ~14MiB 

Status: 

![cpumem](https://i.imgur.com/qB1VL21.png)

![sysstat](https://i.imgur.com/yNSKuuj.png)

UPDATE: added a secure version of the script which downloads cURL CA cert directly from the author's server and then uses secure transmission for downloading lists.
