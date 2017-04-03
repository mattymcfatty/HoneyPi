# HoneyPi

It is astonishingly easy as an attacker to move around on most networks undetected. Let's face it, unless your organization is big enough to have full packet capture with some expensive IDS, you will likely have no idea if there is an attacker on your network. What are the options for home users and small businesses? 

## What if there were a cheap Raspberry Pi device you could plug into your network that masquerades as a juicy target to hackers? 

HoneyPi attempts to offer a reliable indicator of compromise with little to no setup or maintenance costs. There are tons of honey pot options out there, but we leveraged our experience in penetration testing to answer the question *What sorts of activities could be flagged that we generally do when attacking a network?*

That is why HoneyPi tries to keep it simple compared to other honey pots. HoneyPi only flags the three surefire triggers that would catch most attackers:
 1. Port Scanning Activities
 2. RDP Connection Attempts
 3. SMB Connection Attempts

Wrap up this simplicity in a way that is designed to be deployed on a RaspberryPi and you've got a simple honeypot that you can add to your network to get insight when you are under attack.
