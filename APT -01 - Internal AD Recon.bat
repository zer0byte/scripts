@echo off
ipconfig /all >>1.txt
net start >>1.txt
tasklist /v >>1.txt
net user >>1.txt
net localgroup administrators >>1.txt
netstat -ano >>1.txt
net use >>1.txt
net view >>1.txt
net view /domain >>1.txt
net group /domain >>1.txt
net group “domain users” /domain >>1.txt
net group “domain admins” /domain >>1.txt
net group “domain controllers” /domain >>1.txt
net group “exchange domain servers” /domain >>1.txt
net group “exchange servers” /domain >>1.txt
net group “domain computers” /domain >>1.tx
