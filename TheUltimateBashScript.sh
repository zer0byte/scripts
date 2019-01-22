apt-get update && apt-get upgrade
apt-get install ufw
ufw allow 22
ufw enable
apt-get install nmap masscan geoip-bin sshuttle git python-pip libssl-dev libffi-dev python-dev build-essential -y
mkdir /Tools
ls
cd /Tools
wget https://git.io/vpn -O openvpn-install.sh
git clone https://github.com/trustedsec/ptf.git
apt-get install curl git libcurl4-openssl-dev make zlib1g-dev gawk g++ gcc libreadline6-dev libssl-dev libyaml-dev libsqlite3-dev sqlite3 auto$
echo "deb https://ppa.launchpad.net/brightbox/ruby-ng/ubuntu trusty main" | tee -a /etc/apt/sources.list.d/ruby.list
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C3173AA6
apt-get install ruby2.3 ruby2.3-dev bundler -y
git clone https://github.com/wpscanteam/wpscan.git
cd wpscan
bundle install --without test
alias wpscan='/root/Tools/wpscan/./wpscan.rb' 
pip install crackmapexec
pip install webscreenshot
