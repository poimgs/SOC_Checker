#!/bin/bash

# Check if user is root
if [[ $EUID -ne 0 ]]; then
	echo "[!] You must be root"
	exit 1
fi

# Get date of scans from user
date=$1

# Check if logs for specified date is available
if ! [[ -d "../logs/$date" ]]; then
	echo "[!] $date could not be found. Please enter a valid directory path."
	exit 2
fi

cd ../logs/$date
targets=$(ls)

if [[ -z $targets ]]; then
	echo "[!] Nothing found in directory $date. Please conduct a scan to use this script."
	exit 2
fi

# Check number of targets in the date directory
num_targets=$(echo $targets | awk '{print $NF}')

# If number of targets is more than 1, check if user wants to run vuln checker on all or just one of them
if [[ $num_targets > 1 ]]; then
	echo "We found the following targets in the $date directory"
	for target in $targets; do
		echo $target
	done

	read -p "[?] Do you want to run a scan on all targets or just one target? [a/o] " input
	if [[ $input == a ]]; then
		for target in $targets; do
			cd target
			if [[ -d "scans" ]]; then
				cd scans
				
				cd ..
			fi
			cd ..
		done
	elif [[ $input == o ]]; then
		#statements
	fi
else
	# Statement ere
fi