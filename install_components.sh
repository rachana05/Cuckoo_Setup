echo "########################################"
echo "#         CUCKOO MALWARE ANALYZER         #"
echo "########################################"

echo "Downloading Python libraries on UBuntu 18.04"
apt-get install python python-pip python-dev libffi-dev libssl-dev
apt-get install python-virtualenv python-setuptools
apt-get install libjpeg-dev zlib1g-dev swig

echo "Install Developer Tools"
sudo apt-get install build-essential python3-dev python-dev libssl-dev swig

echo "Installing MongoDB"
apt-get install mongodb

echo "Installing PostgreSQL"
apt-get install postgresql libpq-dev

echo "Installing YARA"
wget --no-check-certificate https://files.pythonhosted.org/packages/57/4a/aa0aeb948bb3cd355281ee40401b6673df2f809ed36afc35993c8f02a4d1/yara-python-3.6.3.tar.gz
tar -xvf yara-python-3.6.3.tar.gz
cd yara-python-3.6.3
python setup.py install
cd ..


echo "Installing Pydeep"
wget --no-check-certificate https://files.pythonhosted.org/packages/5c/c2/f36729381c81d59c6f870c55c802f7d92eba29e0f4118e51a122b22a5dc7/pydeep-0.2.tar.gz
tar -xvf pydeep-0.2.tar.gz
cd pydeep-0.2
python setup.py install
cd ..

echo "Installing KVM"
apt-get install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt

echo "Downloading XenAPI"
wget --no-check-certificate https://files.pythonhosted.org/packages/eb/ae/482b173c3d6d8d1c496be862a8a210eaf6d775cd288e08818c15a07259cc/XenAPI-1.2.tar.gz
tar -xvf XenAPI-1.2.tar.gz
cd XenAPI-1.2
python setup.py install
cd ..


echo "Installing tcpdump"
apt-get install tcpdump apparmor-utils
aa-disable /usr/sbin/tmp
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump


echo "Downloading M2Crypto"
wget --no-check-certificate https://files.pythonhosted.org/packages/41/50/7d85dc99b1c4f29eca83873d851ec29a8e484a66b31351e62e30be9db7d1/M2Crypto-0.30.1.tar.gz
tar -xvf M2Crypto-0.30.1.tar.gz
cd M2Crypto-0.30.1
python setup.py install
cd ..


echo "Downloading Python Package - Simple/Typing"
wget --no-check-certificate https://files.pythonhosted.org/packages/ec/cc/28444132a25c113149cec54618abc909596f0b272a74c55bab9593f8876c/typing-3.6.4.tar.gz
tar -xvf typing-3.6.4.tar.gz
cd typing-3.6.4
python setup.py install
cd ..


echo "Install guacd"
apt-get install libguac-client-rdp0 libguac-client-vnc0 libguac-client-ssh0 guacd

echo "Downloading Cuckoo"
git -c http.sslVerify=false clone https://github.com/cuckoosandbox/cuckoo.git

echo "Install Scapy 2.3.2"
wget --no-check-certificate https://files.pythonhosted.org/packages/6d/72/c055abd32bcd4ee6b36ef8e9ceccc2e242dea9b6c58fdcf2e8fd005f7650/scapy-2.3.2.tar.gz
tar -xvf scapy-2.3.2.tar.gz
cd scapy-2.3.2
python setup.py install
cd ..


echo "Install requests 2.13.0"
wget --no-check-certificate https://files.pythonhosted.org/packages/16/09/37b69de7c924d318e51ece1c4ceb679bf93be9d05973bb30c35babd596e2/requests-2.13.0.tar.gz
tar -xvf requests-2.13.0.tar.gz
cd requests-2.13.0
python setup.py install
cd ..

echo "Install wakeonlan -0.2.2)"
wget --no-check-certificate https://files.pythonhosted.org/packages/26/87/4164f76446fb372ce9ff10f9458ac00dade098ef054772ab3333139e8cfa/wakeonlan-0.2.2.tar.gz
tar -xvf wakeonlan-0.2.2.tar.gz
cd wakeonlan-0.2.2
python setup.py install
cd ..

echo "Install unicorn 1.0.1"
wget --no-check-certificate https://files.pythonhosted.org/packages/7d/7f/47fe864fe967e91de2d57677618cffc91bee3918f0a3cdbaa6500b36855e/unicorn-1.0.1.tar.gz
tar -xvf unicorn-1.0.1.tar.gz
cd unicorn-1.0.1
python setup.py install
cd ..

echo "Install SQLAlchemy 1.0.8"
wget --no-check-certificate https://files.pythonhosted.org/packages/4f/1a/a175e650b9671079bb81d04e150b730ccc377342485321839f19689f4ea7/SQLAlchemy-1.0.8.tar.gz
tar -xvf SQLAlchemy-1.0.8.tar.gz
cd SQLAlchemy-1.0.8
python setup.py install
cd ..

echo "INstall SFLock 0.3.5"
 wget --no-check-certificate https://files.pythonhosted.org/packages/70/ce/e9ca6ef6b77c52f39b34d531f6d039779d6514c1327ae0df7ed96176f9ec/SFlock-0.3.5.tar.gz
tar -xvf SFlock-0.3.5.tar.gz
cd SFlock-0.3.5
python setup.py install
cd ..


#git clone https://github.com/volatilityfoundation/volatility.git
#git clone https://github.com/kbandla/pydeep.git
#git clone https://github.com/python/typing.git
#git clone https://github.com/cuckoosandbox/cuckoo.git

echo "Create user"
adduser cuckoo


echo "Vbox Network configurations"
sudo apt install -y net-tools
vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig vboxnet0 --ip <result_server_ip>
vboxmanage modifyvm nameofVM --hostonlyadapter1 vboxnet0
vboxmanage modifyvm nameofVM --nic1 hostonly

#If you want to redirect to the internet
echo "IP table rules to configure IP forwarding from host to guest"
sudo iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A POSTROUTING -t nat -j MASQUERADE
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
sudo apt-get install -y iptables-persistent
sudo gedit /etc/sysctl.conf
echo "Change net.ipv4.ip_forward=1"

echo "Guest configurations for Windows in Virtual Box"
reg add "hklm\software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultUserName /d cuckoo /t REG_SZ /f
reg add "hklm\software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword /d password123 /t REG_SZ /f
reg add "hklm\software\Microsoft\Windows NT\CurrentVersion\WinLogon" /v AutoAdminLogon /d 1 /t REG_SZ /f
reg add "hklm\system\CurrentControlSet\Control\TerminalServer" /v AllowRemoteRPC /d 0x01 /t REG_DWORD /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /d 0x01 /t REG_DWORD /f

echo "Moving agent.py to Desktop"
mv /root/.cuckoo/agent/agent.py /home/adminny10/Desktop
echo "Save agent.py to Windows manually"
////////////////////

echo "Set up LAN Connections Manually in Network options>LAN>tcp/ip settings"
echoIP "Address – 192.168.56.1"
echo "Subnet Mask – 255.255.255.0"
echo "Default Gateway – 192.168.56.1"
echo "DNS Servers – 8.8.8.8/8.8.4.4"

echo "Place agent.py to Windows XP Startup folder C:\Documents and Settings\All Users\Start Menu\Programs\Startup"


echo "Download get.pip.py from https://bootstrap.pypa.io and save in C:\Program Files\python2.7
