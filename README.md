# HoneyPi
Here is a recipe for the HoneyPi as it is now

TODO: Double check that the SMB share is not visible when browsing network (in windows gui)

1. Install Rasbian
2. Make a non-standard user ("pi" user is too easy to guess)
3. connect to wifi
  * sudo nano /etc/network/interfaces 
    * allow-hotplug wlan0 
    * iface wlan0 inet dhcp 
    * wpa-conf /etc/wpa_supplicant/wpa_supplicant.conf 
    * iface default inet dhcp 
  * sudo nano /etc/wpa_supplicant/wpa_supplicant.conf 
    * network={
    * ssid="YOUR_NETWORK_NAME" 
    * psk="YOUR_NETWORK_PASSWORD" 
    * proto=RSN 
    * key_mgmt=WPA-PSK 
    * pairwise=CCMP 
    * auth_alg=OPEN 
    * }
4. Connect via SSH
5. Install PSAD for port monitoring (https://www.digitalocean.com/community/tutorials/how-to-use-psad-to-detect-network-intrusion-attempts-on-an-ubuntu-vps)
  1. sudo apt-get install psad
  2. use psad.conf from this project, but below are some notable changes:
    * EMAIL_ADDRESS (what addres you want to notify of intrusion)
    * HOSTNAME (A unique identifier for this honeypot)
    * PORT_RANGE_SCAN_THRESHOLD       3; 
    * ENABLE_FW_LOGGING_CHECK     N; 
    * IGNORE_PROTOCOLS            udp,igmp; 
    * MAIL_ALERT_PREFIX           [CANARY-SCAN-ALERT]; 
    * MAIL_STATUS_PREFIX          [CANARY-SCAN-status]; 
    * MAIL_ERROR_PREFIX           [CANARY-SCAN-error]; 
    * MAIL_FATAL_PREFIX           [CANARY-SCAN-fatal]; 
6. Make iptables settings persisitent
  * udo apt-get install iptables-persistent 
7. Change iptables to work for psad
  * sudo iptables -A INPUT -j LOG 
  * sudo iptables -A FORWARD -j LOG 
  * sudo iptables-save
8. Install SSMTP for email alerts
  1. sudo apt-get install ssmtp 
  2. sudo pico /etc/ssmtp/ssmtp.conf 
    * root=matty.south@gmail.com 
    * mailhub=smtp.gmail.com:587 
    * hostname=gmail.com 
    * UseSTARTTLS=YES 
    * AuthUser=matty.south 
    * AuthPass= 
    * FromLineOverride=yes 
  3. Test it
    * echo "test message from rpi" | sudo ssmtp -vvv matt.south@trustfoundry.net 
9. Iinstall Tomshoneypot
  1. download python file from http://labs.inguardians.com/tomshoneypot.html
  2. you MUST change these... 
    * interface = '' 
    * myid = 'TEST_CANARY' 
  3. sudo apt-get install python-twisted
  4. add tomshoneypot to startup 
    1. create honeystartup.sh (attached)
      * #!/bin/sh 
      * python tomshoneypot.py >> tomshoneypot.log
    2. Add to crontab 
      * @reboot sh /locationOfStartupScript/honeypotstarter.sh > /home/USERNAME/cronlog 2>&1
10. Rename PI on the network to something tempting like "fserver03" 
  * sudo pico /etc/hostname 
  * sudo nano /etc/hosts
11. Install SMB
  * sudo apt-get install -y  python-qt4 build-essential libssl-dev libffi-dev python-dev libpcap-dev samba samba-common-bin
12. Setup SMB    
  * mkdir /shareddocs
  * chmod 777 /shareddocs 
  * sudo pico /etc/samba/smb.conf (REMOVE ALL THE OTHER STUFF AND ADD THIS)
      * disable netbios = no
      * workgroup = WORKGROUP 
      * wins support = yes 
      * [Documents]
      * comment= Org Docs 
      * path=/shareddocs 
      * only guest = Yes 
      * browseable=No
      * writeable=Yes 
      * create mask=0777 
      * directory mask=0777 
      * public=yes
  13. Put some enticing PDFs in /sharedocs
  14. sudo service smbd restart
  15. Add SMB connection signatures to PSAD (should already be in the included file)
    * sudo pico /etc/psad/signatures 
      * alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB Connection attempt"; flags:S; reference:url,isc.sans.org/port_details.php?port=139; reference:url,secunia.com/advisories/20107; classtype:attempted-admin; psad_id:31331; psad_dl:2;) 
      * alert tcp $EXTERNAL_NET any -> $HOME_NET 139 (msg:"SMB Connection attempt"; flags:S; reference:url,isc.sans.org/port_details.php?port=139; reference:url,secunia.com/advisories/20107; classtype:attempted-admin; psad_id:31332; psad_dl:2;)
  
  
