#!/bin/bash

# Check if user is root
if [[ $EUID -ne 0 ]]; then
	echo "[!] You must be root"
	exit 1
fi

# Check if user provided any arguments
if [[ $# == 0 ]]; then
	echo "Syntax: sudo bash nmap.sh [-a] [-u] <ip_address/Network (CIDR fomat)> "
	echo "options:"
	echo "	a: Runs Nmap with -A flag (Provides more information about machines but easily detectable)"
	echo "	u: Scans UDP ports on top of default TCP ports"
	echo "	h: Help prompt"
	exit 2
fi

# Parse flags from user
while getopts ":hau" opt; do
	case ${opt} in
		h )
			echo "Syntax: sudo bash nmap.sh [-a] [-u] <ip_address/Network (CIDR fomat)> "
			echo "options:"
			echo "	a: Runs Nmap with -A flag (Provides more information about machines but easily detectable)"
			echo "	u: Scans UDP ports on top of default TCP ports"
			echo "	h: Help prompt"
			exit
			;;
		a )
			aggressive=1
			;;
		u )
			udp=1
			;;
		\? )
			echo "Invalid option: $OPTARG" 1>&2
			exit 2
			;;
	esac
done
shift $((OPTIND -1))

# Get ip address/Network from user
target=$1

# If target is a network, parse to only get host identifier
if [[ $target =~ .*/.* ]]; then
	identifier=$(echo $target | awk -F/ '{print $1}')
else
	identifier=$target
fi

# Get date and time to log actions taken
TODAY=$(date +%d%m%y)
DATETIME=$(date)
LOG_PATH="../logs/$TODAY/actions.logs"

if ! [[ -e $LOG_PATH ]]; then
	mkdir -p ../logs/$TODAY
	touch $LOG_PATH
fi

# Create directory and set path to save results
SAVE_PATH="../logs/$identifier/scans"
mkdir -p "$SAVE_PATH"

# Conduct nmap scan on ip address/network
echo "[*] Scanning $target's TCP ports"

# TCP nmap scans
if [[ $aggressive == 1 ]]; then
	# Log nmap scan
	echo "$DATETIME" >> $LOG_PATH
	echo "Aggressive nmap scan conducted on $target" >> $LOG_PATH
	echo "Details saved in logs/$identifier/scans" >> $LOG_PATH
	echo "" >> $LOG_PATH

	# Run nmap scan
	nmap -A -Pn -p- -oA "$SAVE_PATH/nmap_aggressive" $target
else
	# Log nmap scan
	echo "$DATETIME" >> $LOG_PATH
	echo "Silent nmap scan conducted on $target" >> $LOG_PATH
	echo "Details saved in logs/$identifier/scans" >> $LOG_PATH
	echo "" >> $LOG_PATH
	
	# Run nmap scan
	nmap -sS -Pn -p- -oA "$SAVE_PATH/nmap_silent" $target	
fi

echo "[*] Results of TCP scan can be found in logs/$target/scans"

# UDP nmap scans 
if [[ $udp == 1 ]]; then
	# Log nmap scan
	echo "$DATETIME" >> LOG_PATH
	echo "UDP scan conducted on $target" >> LOG_PATH
	echo "Details saved in logs/$target/scans" >> LOG_PATH
	echo "" >> LOG_PATH

	# Run UDP nmap scan
	echo "[*] Scanning $target's UDP ports"
	nmap -sUV -Pn -p- -T4 -v -oA "$SAVE_PATH/nmap_UDP" $target

	echo "[*] Results of scan can be found in logs/$identifier/scans"
fi