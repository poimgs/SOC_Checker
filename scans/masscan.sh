#!/bin/bash

# Check if user is root
if [[ $EUID -ne 0 ]]; then
	echo "[!] You must be root"
	exit 1
fi

# Check if user provided any arguments
if [[ $# == 0 ]]; then
	echo "Syntax: sudo bash masscan.sh <Network (CIDR fomat)> "
	exit 2
fi

# Parse flags from user
while getopts ":h" opt; do
	case ${opt} in
		h )
			echo "Syntax: sudo bash masscan.sh <Network (CIDR fomat)> "
			exit 2
			;;
		\? )
			echo "Invalid option: $OPTARG" 1>&2
			exit 2
			;;
	esac
done
shift $((OPTIND -1))

# Get network from user
network=$1
cidr=$(echo $network | awk -F/ '{print $2}')
identifier=$(echo $network | awk -F/ '{print $1}')
identifier="${identifier}_${cidr}"

# Get date and time to log actions taken
TODAY=$(date +%d%m%y)
DATETIME=$(date)
LOG_PATH="../logs/$TODAY/actions.logs"

if ! [[ -e $LOG_PATH ]]; then
	mkdir -p ../logs/$TODAY
	touch $LOG_PATH
fi

# Create directory and set path to save results
mkdir -p ../logs/$TODAY/$identifier/scans
SAVE_PATH="../logs/$TODAY/$identifier/scans/masscan.txt"

# Log masscan
echo "$DATETIME" >> $LOG_PATH
echo "mass scan conducted on $network" >> $LOG_PATH
echo "Details saved in logs/$TODAY/$identifier/scans" >> $LOG_PATH
echo "" >> $LOG_PATH

# Run masscan
echo "[*] Scanning $network"
masscan $network -p0-65535 --ports U:0-65535 --rate=100000 > $SAVE_PATH

echo "[*] Results of scan can be found in logs/$TODAY/$identifier/scans"