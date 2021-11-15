#!/bin/bash

# Functions

# Help
help() {
	echo "Syntax: sudo bash SOChecker.sh install | scan | attack | analyse"
	echo "options:"
	echo "  install: Install required programs for script to work"
	echo "  scan: Scan ip addresses/networks for open ports"
	echo "  attack: Run common network attacks on Windows and/or Linux machines"
	echo "  analyse: Start web server to analyse logs from scans and attacks"
}

# Check for missing programs
check_programs() {
	uninstalled_programs=()

	# Check for nmap
	if ! [[ -x "$(command -v nmap)" ]]; then
		uninstalled_programs+=( "nmap" )
	fi

	# Check for masscan
	if ! [[ -x "$(command -v masscan)" ]]; then
		uninstalled_programs+=( "masscan" )
	fi

	# Check for hydra
	if ! [[ -x "$(command -v hydra)" ]]; then
		uninstalled_programs+=( "hydra" )
	fi

	# Check for msfconsole
	if ! [[ -x "$(command -v msfconsole)" ]]; then
		uninstalled_programs+=( "metasploit-framework" )
	fi

	# Check for arpspoof
	if ! [[ -x "$(command -v arpspoof)" ]]; then
		uninstalled_programs+=( "dsniff" )
	fi

	# Check for tshark
	if ! [[ -x "$(command -v arpspoof)" ]]; then
		uninstalled_programs+=( "tshark" )
	fi

	# Check for python3-pip
	if ! [[ -x "$(command -v pip3)" ]]; then
		uninstalled_programs+=( "python3-pip" )
	fi
	
	# Check for venv (Python module)
	python3 -c "import venv" 2> /dev/null
	if [[ $? == 1 ]]; then
		uninstalled_programs+=( "python3-venv" )
	fi

	# Check number of uninstalled programs
	if [[ ${#uninstalled_programs[@]} > 0 ]]; then
		echo "[!] This script requires the following programs to work properly:"
		for program in ${uninstalled_programs[@]}; do
			echo $program 
		done

		echo "[!] Please run sudo bash SOChecker.sh install"
		exit 
	fi
}

# Install programs
install_programs() {
	uninstalled_programs=()

	# Check for nmap
	if ! [ -x "$(command -v nmap)" ]; then
		uninstalled_programs+=( "nmap" )
	fi

	# Check for masscan
	if ! [ -x "$(command -v masscan)" ]; then
		uninstalled_programs+=( "masscan" )
	fi

	# Check for hydra
	if ! [ -x "$(command -v hydra)" ]; then
		uninstalled_programs+=( "hydra" )
	fi

	# Check for msfconsole
	if ! [ -x "$(command -v msfconsole)" ]; then
		uninstalled_programs+=( "metasploit-framework" )
	fi

	# Check for arpspoof
	if ! [ -x "$(command -v arpspoof)" ]; then
		uninstalled_programs+=( "dsniff" )
	fi

	# Check for tshark
	if ! [ -x "$(command -v arpspoof)" ]; then
		uninstalled_programs+=( "tshark" )
	fi

	# Check for python3-pip
	if ! [[ -x "$(command -v pip3)" ]]; then
		uninstalled_programs+=( "python3-pip" )
	fi
	
	# Check for venv (Python module)
	python3 -c "import venv" 2> /dev/null
	if [[ $? == 1 ]]; then
		uninstalled_programs+=( "python3-venv" )
	fi
	
	# Check number of uninstalled programs
	if [[ ${#uninstalled_programs[@]} > 0 ]]; then
		echo "[!] This script requires the following programs to work properly: "
		for program in ${uninstalled_programs[@]}; do
			echo $program 
		done

		# Check if user wants to install programs
		read -p "[?] Install the above programs? [Y/n] " input
		if [[ $input == "n" ]]; then
			echo "[!] Programs not installed, the script will not continue"
			exit
		fi

		# Install programs
		sudo apt-get update
		for program in ${uninstalled_programs[@]}; do
			sudo apt-get -y install $program
		done

	# Inform user that nothing needs to be installed
	else
		echo "[*] All required programs are already installed"
	fi

}

# Scan machine/network
scan() {
	# Check if programs have been installed
	check_programs

	# change directory to scans to more easily access scripts
	cd scans

	# Check if user wants to scan a single or network and the type of scan to be conducted
	read -p "[?] Are you scanning an IP or a network? [I/n] " scan_range
	if [[ $scan_range == "n" ]]; then
		read -p "[?] Do you want to use nmap or masscan to scan the network? [N/m] " scan_technique
		read -p "[?] Network to scan: (CIDR format) " scan_target
		if ! [[ $scan_target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
			echo "[!] Please enter a valid network in CIDR format"
			exit 2
		fi
	else
		read -p "[?] IP address to scan: " scan_target
		if ! [[ $scan_target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
			echo "[!] Please enter a valid IP address"
			exit 2
		fi
	fi

	# Check what kind of nmap scan the user wants to conduct
	if [[ $scan_range != "n" || $scan_technique != "m" ]]; then
		read -p "[?] Silent or Aggressive nmap scan? [S/a] " nmap_aggressiveness
		if [[ $nmap_aggressiveness == "a" ]]; then
			read -p "[?] Scan UDP ports? [y/N] " udp_scan
		fi
	fi

	# Begin scanning based on user input
	if [[ $scan_technique == "m" ]]; then
		# Masscan
		sudo bash masscan.sh $scan_target
	else
		# Nmap scan
		if [[ $nmap_aggressiveness == "a" && $udp_scan == "y" ]]; then
			sudo bash nmap.sh -a -u $scan_target
		elif [[ $nmap_aggressiveness != "a" && $udp_scan == "y" ]]; then
			sudo bash nmap.sh -u $scan_target
		elif [[ $nmap_aggressiveness == "a" && $udp_scan != "y" ]]; then
			sudo bash nmap.sh -a $scan_target
		else
			sudo bash nmap.sh $scan_target
		fi
	fi
}

# Attack machine/network
attack() {
	# Check if programs have been installed 
	check_programs

	# change directory to scans to more easily access scripts
	cd attacks

	# Check which attacks user wants to conduct
	read -p "[?] Are you attacking a Linux or Windows machine? [L/w] " OS

	if [[ $OS == "w" ]]; then
		read -p "[?] Run kerberos attack? [Y/n] " kerberos
		read -p "[?] Run Man in the Middle attack? [y/N] " mitm
	else
		read -p "[?] Run brute force SSH attack? [Y/n] " brute_force_ssh
		read -p "[?] Run Man in the Middle attack? [y/N] " mitm
	fi

	# Kerberos attack
	if [[ $OS == "w" && $kerberos != "n" ]]; then
		# Signal to user that details to be inputted pertain to kerberos attack
		echo "=========================="
		echo "Initiating Kerberos attack"
		echo "=========================="

		# Get IP address
		read -p "[?] IP address: " IP
		if ! [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
			echo "[!] Please enter a valid IP address"
			exit 2
		fi

		# Get domain name
		read -p "[?] Domain name: " domain
		if [[ -z $domain ]]; then
			echo "[!] Please don't keep pressing enter, we need an entry for this!"
			exit 2
		fi

		# Use default kerberos list
		user_file="../lists/usernames/kerberos_list.txt" 

		# Run Kerberos Brute force attack
		bash brute_force_kerberos.sh -d $domain -u $user_file $IP
	fi

	# SSH brute force attack
	if [[ $OS != "w" && $brute_force_ssh != "n" ]]; then 
		# Signal to user that details to be inputted pertain to SSH brute force attack
		echo "================================="
		echo "Initiating SSH Brute Force attack"
		echo "================================="

		# Get IP address
		read -p "[?] IP address: " IP
		if ! [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
			echo "[!] Please enter a valid IP address"
			exit 2
		fi

		# Get port number (optional)
		read -p "[?] Port number: (Default 22) " port
		if [[ -z $port ]]; then
			port=22
		fi

		# Get username/username list
		read -p "[?] username or username file [u/F] " input
		if [[ $input == "u" ]]; then
			read -p "[?] Enter username: " username
		else
			read -p "[?] top-usernames-shortlist or cirt-default-usernames? [T/c] " username_list 
			if [[ $username_list == "c" ]]; then
				username_list="../lists/usernames/cirt-default-usernames.txt"
			else
				username_list="../lists/usernames/top-usernames-shortlist.txt"
			fi
		fi

		# Get password/password list
		read -p "[?] password or password file [p/F] " input
		if [[ $input == "p" ]]; then
			read -p "[?] Enter password: " password
		else
			read -p "[?] 2020-200_most_used_passwords or cirt-default-passwords or darkweb2017-top10000 [M/c/d] " password_list
			if [[ $password_list == "d" ]]; then
				password_list="../lists/passwords/darkweb2017-top10000.txt"
			elif [[ $password_list == "c" ]]; then
				password_list="../lists/passwords/cirt-default-passwords.txt"
			else
				password_list="../lists/passwords/2020-200_most_used_passwords.txt"
			fi
		fi

		# Run SSH Brute force attack
		if [[ -n $username && -n $password ]]; then
			bash brute_force_SSH.sh -s $port -u $username -p $password $IP
		elif [[ -n $username_list && -n $password ]]; then
			bash brute_force_SSH.sh -s $port -U $username_list -p $password $IP
		elif [[ -n $username && -n $password_list ]]; then
			bash brute_force_SSH.sh -s $port -u $username -P $password_list $IP
		else 
			bash brute_force_SSH.sh -s $port -U $username_list -P $password_list $IP
		fi

	fi

	# Man in the Middle attack
	if [[ $mitm == "y" ]]; then
		# Signal to user that details to be inputted pertain to SSH brute force attack
		echo "==================================="
		echo "Initiating Man in the Middle attack"
		echo "==================================="

		# Get interface name
		read -p "[?] Interface name: (Default: eth0) " interface
		if [[ -z $interface ]]; then
			interface="eth0"
		fi

		# Get target IP address
		read -p "[?] target IP address: " target
		if [[ -z $target ]]; then
			echo "[!] Please don't keep pressing enter, we need an entry for this!"
			read -p "[?] target IP address: " target
		fi

		# Get router IP address
		read -p "[?] router IP address: " router
		if [[ -z $router ]]; then
			echo "[!] Please don't keep pressing enter, we need an entry for this!"
			read -p "[?] router IP address: " router
		fi

		# Run Man in th Middle attack
		sudo bash MitM.sh -i $interface -t $target -r $router
	fi
}

# Analyse logs using streamlit application
analyse() {

	# app folder contains Python code for running streamlit application
	cd app 

	# Create virtual environment if it does not exist
	if ! [[ -d "env" ]]; then
		echo "[*] Creating Python virtual environment in app folder"

		# Create python virtual environment
		python3 -m venv env 

		# Activate virtual environment
		source env/bin/activate

		# Install requirements and eter no arguments for prompt
		pip3 install -r requirements.txt

		echo "[*] Created Python virtual environment"
	fi

	# Activate virtual environment
	source env/bin/activate

	# Run streamlit application
	echo "" | streamlit run app.py
}

# Script

# Check if user is root
if [[ $EUID -ne 0 ]]; then
	echo "[!] You must have root permissions to run this script properly"
	exit 1
fi

# Parse argument
argument=$1

if [[ $argument == "install" ]]; then
	install_programs
elif [[ $argument == "scan" ]]; then
	scan
elif [[ $argument == "attack" ]]; then
	attack
elif [[ $argument == "analyse" ]]; then
	analyse
else
	echo "[!] You did not enter a valid argument."
	help
	exit 2
fi
