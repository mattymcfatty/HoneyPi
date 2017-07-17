# HoneyPi

It is astonishingly easy as an attacker to move around on most networks undetected. Let's face it, unless your organization is big enough to have full packet capture with some expensive IDS, you will likely have no idea if there is an attacker on your network. What are the options for home users and small businesses? 

## What if there were a cheap Raspberry Pi device you could plug into your network that masquerades as a juicy target to hackers? 

HoneyPi attempts to offer a reliable indicator of compromise with little to no setup or maintenance costs. There are tons of honeypot options out there, but we leveraged our experience in penetration testing to answer the question *What sorts of activities could be flagged that we generally do when attacking a network?*

That is why HoneyPi tries to keep it simple compared to other honeypots. HoneyPi only flags the three surefire triggers that would catch most attackers:
 1. Port Scanning Activities
 2. FTP Connection Attempts
 3. Telnet Connection Attempts

Wrap up this simplicity in a way that is designed to be deployed on a RaspberryPi and you've got a simple honeypot that you can add to your network to get insight when you are under attack.

## Installation

You'll need a Raspberry Pi running Rasbian.

From the Pi, do this:
 1. wget https://github.com/mattymcfatty/HoneyPi/archive/v01.zip
 2. unzip v01.zip
 3. cd HoneyPi-01
 4. chmod +x *.sh
 4. sudo ./honeyPiInstaller.sh
 5. Follow the prompts.
 
Please note: Installing this will do some things to your Raspberry Pi. Most notably, it will change your iptables. Please proceed with caution if you are using this Raspberry Pi for other purposes.
