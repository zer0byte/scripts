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
apt-get install nmap masscan net-tools geoip-bin sshuttle git python-pip libssl-dev libffi-dev phantomjs python-dev build-essential python3-pip -y
apt-get install curl git locate libcurl4-openssl-dev make zlib1g-dev gawk g++ gcc libreadline6-dev libssl-dev libyaml-dev libsqlite3-dev sqlite3 auto$
apt-get install python-requests
echo " "
echo " "
mkdir Tools
echo " "
echo " "
cd Tools
echo " "
echo " "
echo "[+] Installing dirsearch [+]"
echo " "
echo " "
git clone https://github.com/maurosoria/dirsearch.git
echo " "
echo " "
wget https://git.io/vpn -O openvpn-install.sh
echo " "
echo " "
echo "[+] Installing Pentester Framework [+]"
echo " "
echo " "
git clone https://github.com/trustedsec/ptf.git
echo " "
echo " "
echo "[+] Installing Sublist3r [+]"
echo " "
echo " "
git clone https://github.com/aboul3la/Sublist3r.git
echo " "
echo " "
echo "[+] Installing Responder [+]"
echo " "
echo " "
git clone https://github.com/SpiderLabs/Responder.git
echo " "
echo " "
echo "[+] Installing Nikto [+]"
echo " "
echo " "
git clone https://github.com/sullo/nikto.git
echo " "
echo " "
echo "[+] Installing PwnDB [+]"
echo " "
echo " "
git clone https://github.com/davidtavarez/pwndb
apt install apt-transport-https
apt install apt-transport-tor
cd /root/Tools/pwndb
pip install -r requirements.txt
echo " "
echo " "
echo "[+] Installing WPScan [+]"
echo " "
echo " "
echo "deb https://ppa.launchpad.net/brightbox/ruby-ng/ubuntu trusty main" | tee -a /etc/apt/sources.list.d/ruby.list
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C3173AA6
apt-get install ruby2.3 ruby2.3-dev bundler -y
git clone https://github.com/wpscanteam/wpscan.git
cd wpscan
bundle install --without test
alias wpscan='/root/Tools/wpscan/./wpscan.rb'
echo " "
echo " "
echo "[+] Installing Droopescan [+]"
echo " "
echo " "
pip install droopescan
echo " "
echo " "
echo "[+] Installing Crackmapexc [+]"
echo " "
echo " "
pip install crackmapexec
echo " "
echo " "
echo "[+] Installing WebScreenshot [+]"
echo " "
echo " "
pip install webscreenshot
echo " "
echo " "
echo "[+] Installing Amass [+]"
echo " "
echo " "
apt install snapd
snap install amass
echo " "
echo " "
echo "[+] Installing Impacket [+]"
echo " "
echo " "
apt install python3-pip
git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
pip3 install -r /opt/impacket/requirements.txt
python3 /opt/impacket/setup.py install
echo " "
echo " "
echo "[+] Installing Eyewitness [+]"
echo " "
echo " "
cd /root/Tools
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness/
cd Python/
cd setup/
./setup.sh
echo " "
echo " "
echo "[+] Installing Dirb [+]"
echo " "
echo " "
cd /root/Tools
git clone https://salsa.debian.org/pkg-security-team/dirb.git
cd dirb
bash ./configure
make
