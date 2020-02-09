#!/bin/bash

echo "[+] Starting Install [+]"
echo "[+] Upgrade installed packages to latest [+]"
apt-get update && apt-get upgrade
apt-get autoclean
echo " "
echo " "
echo "[+] Installing Uncomplicated Firewall [+]"
apt-get install ufw
echo " "
echo " "
echo "[+] Configuring Uncomplicated Firewall [+]"
ufw allow 22
echo " "
echo " "
ufw enable
echo " "
echo " "
apt-get install nmap masscan geoip-bin sshuttle git python-pip libssl-dev libffi-dev python-dev build-essential -y
apt-get install curl git libcurl4-openssl-dev make zlib1g-dev gawk g++ gcc libreadline6-dev libssl-dev libyaml-dev libsqlite3-dev sqlite3 auto$
apt-get install python-requests
echo " "
echo " "
mkdir Tools
ls
echo " "
echo " "
cd Tools
echo " "
echo " "
echo "installing dirsearch"
git clone https://github.com/maurosoria/dirsearch.git
wget https://git.io/vpn -O openvpn-install.sh
git clone https://github.com/trustedsec/ptf.git
git clone https://github.com/aboul3la/Sublist3r.git
git clone https://github.com/SpiderLabs/Responder.git
git clone https://github.com/davidtavarez/pwndb
apt install apt-transport-https
apt install apt-transport-tor
echo "deb https://ppa.launchpad.net/brightbox/ruby-ng/ubuntu trusty main" | tee -a /etc/apt/sources.list.d/ruby.list
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C3173AA6
apt-get install ruby2.3 ruby2.3-dev bundler -y
git clone https://github.com/wpscanteam/wpscan.git
cd wpscan
bundle install --without test
alias wpscan='/root/Tools/wpscan/./wpscan.rb' 
pip install crackmapexec
pip install webscreenshot
cd /root/Tools/pwndb
pip install -r requirements.txt
