#!/bin/bash

priv_check()
{
if [ "$(whoami)" != "root" ]
then
	echo -e "This tool must be run as root!\nExiting!"
	exit
fi
}
priv_check

RED='\033[0;31m'
NC='\033[0m'
IPS=db1.txt

echo -e "${RED}[+]${NC} Hunter has started analyzing: \n"
#Function to scan exported objects and to scan their hashes via VirusTotal:
objects()
{
	#Creating a file for checked hashes for efficency:
	touch checked_hashes.txt
	while true
	do
		for i in $(ls /tmp/tshark_objects)
		do
			sha256sum /tmp/tshark_objects/$i 1>> /tmp/hashes.txt
		done
		#Remove duplicates:
		cat /tmp/hashes.txt > /tmp/tmp_hash
		rm /tmp/hashes.txt
		cat /tmp/tmp_hash | sort -u | uniq > /tmp/hashes.txt
		awk '{print $1}' /tmp/hashes.txt > new_hashes.txt
		#stam.txt is just to check that the script works and has a malicious md5 hash inside:
		#for j in $(cat stam.txt)
		for j in $(cat new_hashes.txt)
		do
			ALREADY_CHECKED=$(cat checked_hashes.txt | grep $j)
			if [ "$ALREADY_CHECKED" == "" ]
			then
				#Passes the hash to VT to check if it's malicious:
				echo -e "${RED}ALERT:\n"
				printf "MALICIOUS FILE FOUND: "
				curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' --form apikey="6212504be2f223956c0daf2cf35284cc8708b53b2ec6433ee1033a1db20db5be" --form resource="$j" | awk -F 'positives\":' '{print "VT Hits" ":" $2}' | awk -F ' ' ' {print $1$2$3$4$5$6$7}' | sed 's|["}]||g' | tee -a malicious_f.log
				echo $j >> checked_hashes.txt
				echo "Saved to $PWD/malicious_f.log"
			fi
		done	
	done
}
# Function that scans the network and compares the traffic to the given database: 
bingo()
{
	FILTER=""
	for URL in $(cat $IPS)
	do
		# Convert URL's to IP addresses:
		IS_VALID_HOST=$(dig +short $URL)
		IS_IP=$(echo $URL | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
		if [ "$IS_VALID_HOST" != "" ] || [ "$IS_IP" != "" ]
		then
			FILTER="$FILTER || host $URL"
		fi
	done
	FILTER="${FILTER:4}"
	tshark -P -i any -t 'ad' -N n -f "$FILTER" -w live_traffic.pcapng & 
	tshark -Q -P -i any -t 'ad' -N n -f "$FILTER" --export-objects http,/tmp/tshark_objects -b duration:5 &>/dev/null
}
# Saves alerts of accessed IPs and URLs to a log file:
bingo | tee -a ALERTS.log &
objects
