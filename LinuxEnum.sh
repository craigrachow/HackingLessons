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

# Services Listings
systemctl list-units --type=service

# Bash History
history

# Cronjobs
crontab -l

#file Listing (maybe tree instead)
pwd
ls -l ~/
ls -l /tmp
ls -l 
ls -l /home


