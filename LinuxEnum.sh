#!/bin/bash
# to download
# mkdir ~/nishang/ && git clone https://github.com/samratashok/nishang.git ~/nishang

# OS and Kernal Info
echo "#OS and Kernal Info"
uname -a
id
whoami && hostname
ifconfig | grep ip
ip
netstat


# Bash History
history

# Cronjobs
crontab -l

#file Listing
pwd
ls -l ~/
ls -l /tmp
ls -l 
ls -l /home


