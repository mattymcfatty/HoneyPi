#!/bin/bash

#check root
if [ $UID -ne 0 ]
then
 echo "Please run this script as root: sudo honeyPI.sh"
 exit 1
fi

####Disclaimer!###
if whiptail --yesno "Hey Hey! You're about to install honeyPi to turn this Raspberry Pi into an IDS/honeypot. Congratulations on being so clever! This install process will change some things on your Pi. Most notably, it will flush your iptables and turn up logging. There is no UNINSTALL script, so think hard about not doing this if you plan to use your Pi for other things. Select 'Yes' if you're cool with all that or 'No' to stop now." 20 60
then
  echo "continue"
else
  exit 1
fi

####Change password if you haven't yet###
if [ $SUDO_USER == 'pi' ]
then
 if whiptail --yesno "You're currently logged in as default pi user. If you haven't changed the default password 'raspberry' would you like to do it now?" 20 60
 then
  passwd
 fi
fi

####Install Debian updates ###
if whiptail --yesno "Let's install some updates. Answer 'no' if you are just experimenting and want to save some time (updates might take 15 minutes or more). Otherwise, shall we update now?" 20 60
then
 apt-get update
 apt-get dist-upgrade
fi


####Name the host something enticing ###
sneakyname=$(whiptail --inputbox "Let's name your honeyPi something enticing like 'SuperSensitiveServer'. Well maybe not that obvious, but you get the idea. Remember, hostnames cannot contain spaces or most special chars. Best to keep it to just alphanumeric and less thaann 24 characters." 20 60 3>&1 1>&2 2>&3)
echo $sneakyname > /etc/hostname
echo "127.0.0.1 $sneakyname" >> /etc/hosts

####Install PSAD ###
whiptail --infobox "Installing a bunch of software like the log monitoring service and other dependencies...\n" 20 60
apt-get -y install psad msmtp msmtp-mta python-twisted iptables-persistent libnotify-bin fwsnort raspberrypi-kernel-headers

###Choose Notification Option###
OPTION=$(whiptail --menu "Choose how you want to get notified:" 20 60 5 "email" "Send me an email" "script" "Execute a script" "blink" "Blink a light on your Raspberry Pi" 3>&2 2>&1 1>&3)
emailaddy=test@example.com
enablescript=N
externalscript=/bin/true
alertingmethod=ALL
check=1

case $OPTION in
	email)
		emailaddy=$(whiptail --inputbox "Mmmkay. Email is a pain to set up. We have defaults for gmail so use that if you have it. What's your email address?" 20 60 3>&1 1>&2 2>&3)
        	msmtp --configure $emailaddy > msmtprc
        	echo "account default : $emailaddy" >> msmtprc
        	sed -i 's/passwordeval.*/password XXX/g' msmtprc
        	sed -i 's/# -.*/### Just replace XXX with your app password/g' msmtprc
        	sed -i 's/#  .*/### and press Ctrl-X to quit and save/g' msmtprc
        	cp msmtprc /etc/
		check=30
		whiptail --msgbox "Now, create an 'App Password' for your gmail account (google it if you don't know how). Because we don't want to assign your password to any variables, you have to manually edit the smtp configuration file on the next screen. Save and exit the editor and I'll see you back here." 20 60
		pico /etc/msmtprc
		whiptail --msgbox "Welcome back! Well Done! Here comes a test message to your email address..." 20 60
		echo "test message from honeyPi" | msmtp -vvv $emailaddy
		if whiptail --yesno "Cool. Now wait a couple minutes and see if that test message shows up. 'Yes' to continue or 'No' to exit and mess with your smtp config." 20 60
 		then
  			echo "Continue"
		else
			exit 1
 		fi

	;;
	script)
		externalscript=$(whiptail --inputbox "Enter the full path and name of the script you would like to execute when an alert is triggered:" 20 60 3>&1 1>&2 2>&3)
		enablescript=Y
		alertingmethod=noemail
	;;
	blink)
		enablescript=Y
		alertingmethod=noemail
		externalscript="/usr/bin/python /root/honeyPi/blinkonce.py"
	;;
esac

###update vars in configuration files
sed -i "s/xhostnamex/$sneakyname/g" psad.conf
sed -i "s/xemailx/$emailaddy/g" psad.conf
sed -i "s/xenablescriptx/$enablescript/g" psad.conf
sed -i "s/xalertingmethodx/$alertingmethod/g" psad.conf
sed -i "s=xexternalscriptx=$externalscript=g" psad.conf
sed -i "s/xcheckx/$check/g" psad.conf


###Wrap up everything and exit
whiptail --msgbox "Configuration files created. Next we will move those files to the right places." 20 60
mkdir /root/honeyPi
cp blink*.* /root/honeyPi
cp psad.conf /etc/psad/psad.conf
iptables --flush
iptables -A INPUT -p igmp -j DROP
#too many IGMP notifications. See if that prevents it
iptables -A INPUT -j LOG
iptables -A FORWARD -j LOG
service netfilter-persistent save
service netfilter-persistent restart
psad --sig-update
service psad restart
cp mattshoneypot.py /root/honeyPi
(crontab -l 2>/dev/null; echo "@reboot python /root/honeyPi/mattshoneypot.py &") | crontab -
python /root/honeyPi/mattshoneypot.py &
ifconfig
printf "\n \n ok, now reboot and you should be good to go. Then, go portscan this honeyPi from another machine and see if you get an alert!\n"

