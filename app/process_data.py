import xmltodict
import re
from typing import Union
import os
import helper

# Path to logs
LOGS_PATH = os.path.join("..", "logs")

def get_targets(log_date_path: str) -> list:
	"""Checks for ip patterns in directory path and retuns all ip patterns"""
	log_date_path_contents = os.listdir(log_date_path)

	# Get ip addresses/Networks from logs directory
	targets_found = []
	target_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}_?\d{0,2}?")

	for item in log_date_path_contents:
		if target_pattern.match(item):
			targets_found.append(item.replace("_", "/"))

	return targets_found

def parse_scans_logs(type_of_ip: str, path_to_scans: str) -> dict:
	"""Parse scans logs in directory and return dictionary containing relevant information"""

	def parse_nmap_host_information(host_information: dict) -> dict:
		"""Parse host information from nmap scans"""
		relevant_data = {
			"ip_address": None,
			"host_state": host_information["status"]["@state"],
			"OS_name": None,
			"OS_accuracy": None,
			"mac_address": None,
			"mac_address_vendor": None,
			"ports": None 
		}

		# If host_information["address"] is of type list, mac address can be extracted
		if isinstance(host_information["address"], list):
			relevant_data["ip_address"] = host_information["address"][0]["@addr"]
			relevant_data["mac_address"] = host_information["address"][1]["@addr"]
			relevant_data["mac_address_vendor"] = host_information["address"][1]["@vendor"]
		else:
			relevant_data["ip_address"] = host_information["address"]["@addr"]

		# If os can be found, os name and accuracy can be extracted
		if host_information.get("os"):
			if isinstance(host_information["os"]["osmatch"], list):
				relevant_data["OS_name"] = host_information["os"]["osmatch"][0]["@name"]
				relevant_data["OS_accuracy"] = host_information["os"]["osmatch"][0]["@accuracy"]
			else:
				relevant_data["OS_name"] = host_information["os"]["osmatch"]["@name"]
				relevant_data["OS_accuracy"] = host_information["os"]["osmatch"]["@accuracy"]

		# If port can be found, ports information can be extracted
		if host_information["ports"].get("port"):

			# If port is in the form of a list, multiple ports are open, else only 1 port is open
			if isinstance(host_information["ports"]["port"], list):
				ports = []

				for port in host_information["ports"]["port"]:
					port_information = {
						"number": port["@portid"],
						"state": port["state"]["@state"],
						"transport_protocol": port["@protocol"],
						"service": None,
						"product": None,
						"version": None
					}

					# If service exists, port service information can be extracted
					if port.get("service"):
						port_information["service"] = port["service"]["@name"]
						if port["service"].get("@product"):	
							port_information["product"] = port["service"]["@product"]
						if port["service"].get("@version"):	
							port_information["version"] = port["service"]["@version"]

					ports.append(port_information)

				relevant_data["ports"] = ports
			else:
				port = host_information["ports"]["port"]
				port_information = {
					"number": port["@portid"],
					"state": port["state"]["@state"],
					"transport_protocol": port["@protocol"],
					"service": None,
					"product": None,
					"version": None
				}

				if port.get("service") is not None:
					port_information["service"] = port["service"]["@name"]
					if port["service"].get("@product") is not None:	
						port_information["product"] = port["service"]["@product"]
					if port["service"].get("@version") is not None:	
						port_information["version"] = port["service"]["@version"]

				relevant_data["ports"] = [port_information]

		return relevant_data

	def parse_masscan(path_to_masscan: str) -> dict:
		"""Parse masscan information"""
		with open(path_to_masscan, "r") as f:
			masscan_data = f.readlines()

		# Store ips information
		ips_information = {}

		# Get relevant data from masscan_data
		for ip_information in masscan_data:
			split_ip_information = ip_information.split()

			ip_address = split_ip_information[5]
			open_port, transport_protocol = split_ip_information[3].split("/") 

			# Parse port information into similar format as nmap above
			port_information = {
				"number": open_port,
				"state": "open",
				"transport_protocol": transport_protocol,
				"service": None,
				"product": None,
				"version": None
			}

			# Parse host information into similar format as nmap above
			if ip_address not in ips_information:
				ips_information[ip_address] = {
					"ip_address": ip_address,
					"host_state": "up",
					"OS_name": None,
					"OS_accuracy": None,
					"mac_address": None,
					"mac_address_vendor": None,
					"ports": [port_information]
				}

			else:
				ips_information[ip_address]["ports"].append(port_information)

		return ips_information
	
	# After definition of inner functions
	scans_done = os.listdir(path_to_scans)

	if type_of_ip == "ip_address":

		# Prioritise getting aggressive nmap scan if available
		if "nmap_aggressive.xml" in scans_done:
			# Read xml file and parse into python dictonary
			path_to_xml = os.path.join(path_to_scans, "nmap_aggressive.xml")
			with open(path_to_xml, "r") as f:
				nmap_xml = f.read()

			nmap_dict = xmltodict.parse(nmap_xml)
			host_information = nmap_dict["nmaprun"]["host"]

			relevant_data = parse_nmap_host_information(host_information)

			return relevant_data, "nmap_aggressive"

		# Get the silent nmap scan if aggressive scan is not available
		if "nmap_silent.xml" in scans_done:
			# Read xml file and parse into python dictonary
			path_to_xml = os.path.join(path_to_scans, "nmap_silent.xml")
			with open(path_to_xml, "r") as f:
				nmap_xml = f.read()

			nmap_dict = xmltodict.parse(nmap_xml)
			host_information = nmap_dict["nmaprun"]["host"]

			relevant_data = parse_nmap_host_information(host_information)

			return relevant_data, "nmap_silent"

	if type_of_ip == "network":

		# Prioritise getting aggressive nmap scan if available
		if "nmap_aggressive.xml" in scans_done:
			# Read xml file and parse into python dictonary
			path_to_xml = os.path.join(path_to_scans, "nmap_aggressive.xml")
			with open(path_to_xml, "r") as f:
				nmap_xml = f.read()

			nmap_dict = xmltodict.parse(nmap_xml)

			# Store relevant data from parsed xml file
			ips_information = {}

			# Get general information for each IP
			for host_information in nmap_dict["nmaprun"]["host"]:
				relevant_data = parse_nmap_host_information(host_information)
				ip_address = relevant_data["ip_address"]
				ips_information[ip_address] = relevant_data

			return ips_information, "nmap_aggressive"

		# Get the silent nmap scan if aggressive scan is not available
		if "nmap_silent.xml" in scans_done:
			# Read xml file and parse into python dictonary
			path_to_xml = os.path.join(path_to_scans, "nmap_silent.xml")
			with open(path_to_xml, "r") as f:
				nmap_xml = f.read()

			nmap_dict = xmltodict.parse(nmap_xml)

			# Store relevant data from parsed xml file
			ips_information = {}

			# Get general information for each IP
			for host_information in nmap_dict["nmaprun"]["host"]:
				relevant_data = parse_nmap_host_information(host_information)
				ip_address = relevant_data["ip_address"]
				ips_information[ip_address] = relevant_data

			return ips_information, "nmap_silent"

		# Get the masscan if silent nmap scan is not available 
		if "masscan.txt" in scans_done:
			# Get masscan data
			path_to_masscan = os.path.join(path_to_scans, "masscan.txt")
			ips_information = parse_masscan(path_to_masscan)

			return ips_information, "masscan"

def parse_attacks_logs(path_to_attacks: str) -> dict:
	"""Parse attacks logs in directory and return dictionary containing relevant information"""

	def parse_brute_force_SSH(path_to_attacks: str) -> list:
		"""Parse brute force SSH logs and return relevant information"""
		path_to_brute_force_SSH = os.path.join(path_to_attacks, "brute_force_SSH.txt")
		with open(path_to_brute_force_SSH, "r") as f:
			lines = f.readlines()

		# Group credentials found by command execution
		logs = []

		# Pattern to check if command was run to attack IP address
		start_of_new_hydra_attack_pattern = re.compile(r"# Hydra.*run at \d{4}-\d{2}-\d{2}.*")

		# Pattern to find usernames and passwords used
		username_pattern = re.compile(r"-l (.*) -[pP]")
		username_list_pattern = re.compile(r"-L (.*) -[pP]")

		password_pattern = re.compile(r"-p (.*) -s")
		password_list_pattern = re.compile(r"-P (.*) -s")

		# Pattern to get SSH port
		port_pattern = re.compile(r"-s (\d+) -o")

		# Pattern to get login and password information
		credentials_login_pattern = re.compile(r"login: (.*) password")
		credentials_password_pattern = re.compile(r"password: (.*)")

		# Store relevant information from logs
		grouped_log = {}

		for index, line in enumerate(lines):

			# Group new set of credentials information when new command is ran
			if start_of_new_hydra_attack_pattern.match(line):

				# Before re-initialising grouped log, append current grouped log to list of logs
				if index > 0:
					logs.append(grouped_log)

				# Get relevant information from line
				splitted_line = line.split()
				time = splitted_line[6]
				ip = splitted_line[8]
				port = port_pattern.search(line).group(1)

				grouped_log = {
					"time": time,
					"ip": ip,
					"port": port,
					"username": None,
					"username_list": None,
					"password": None,
					"password_list": None,
					"credentials": None
				}

				# Get credentials used TO brute force
				if username_pattern.search(line):
					username = username_pattern.search(line).group(1)
					grouped_log["username"] = username	

				if username_list_pattern.search(line):
					matched = username_list_pattern.search(line).group(1)
					username_list = matched.split("/")[-1]
					grouped_log["username_list"] = username_list

				if password_pattern.search(line):
					password = password_pattern.search(line).group(1)
					grouped_log["password"] = password

				if password_list_pattern.search(line):
					matched = password_list_pattern.search(line).group(1)
					password_list = matched.split("/")[-1]
					grouped_log["password_list"] = password_list

				# If there is only line, it means that it was ran one time, with no credentials found, so append it to list of logs
				if len(lines) == 1:
					logs.append(grouped_log)

				# If it's the last iteration, append the last grouped log
				if len(lines) > 1 and index == len(lines) - 1:
					logs.append(grouped_log)

			else:
				# Get credentials found FROM brute force
				login = credentials_login_pattern.search(line).group(1)
				password = credentials_password_pattern.search(line).group(1)

				credential_info = {
					"login": login,
					"password": password
				}

				if grouped_log["credentials"] is None:
					grouped_log["credentials"] = [credential_info]
				else:
					grouped_log["credentials"].append(credential_info)

				# If it's the last iteration, append the last grouped log
				if index == len(lines) - 1:
					logs.append(grouped_log)

		return logs

	def parse_brute_force_kerberos(path_to_attacks: str) -> list:
		"""Parse brute force kerberos logs and return relevant information"""
		path_to_brute_force_kerberos = os.path.join(path_to_attacks, "brute_force_kerberos.txt")
		with open(path_to_brute_force_kerberos, "r") as f:
			lines = f.readlines()

		# Store grouped kerberos logs into list
		relevant_kerberos_data = []

		# Regex that matches first line of new kerberos attack
		date_pattern = re.compile(r"\w{3} \w{3} \d+ \d{2}:\d{2}:\d{2} \w{2} \+\d{2} \d{4}")

		kerberos_log = {}
		for index, line in enumerate(lines):

			# Check if line is start of new kerberos attack
			if date_pattern.match(line):

				# Get ip and domain information logs
				time = " ".join(line.split()[3:5])
				username_list = lines[index+1].split()[-1]
				ip = lines[index+4].split()[-1]
				domain = lines[index+6].split()[-1][:-3]

				kerberos_log = {
					"time": time,
					"username_list": username_list,
					"ip": ip,
					"domain": domain,
					"users": None
				}

			if "is present" in line:
				user = line.split()[4][1:-1]
				if kerberos_log["users"] is None:
					kerberos_log["users"] = [user]
				else:
					kerberos_log["users"].append(user)

			if "resource (kerberos_enum.rc)> exit" in line:
				relevant_kerberos_data.append(kerberos_log)

		return relevant_kerberos_data

	# Start of non-helper functions
	relevant_data = {
		"brute_force_SSH": None,
		"brute_force_kerberos": None,
		"Man_in_the_Middle": None
	}

	# If brute force on SSH service was conducted, extract relevant info
	if helper.brute_force_SSH_conducted(path_to_attacks):
		parsed_brute_force_SSH_logs = parse_brute_force_SSH(path_to_attacks)
		relevant_data["brute_force_SSH"] = parsed_brute_force_SSH_logs

	if helper.brute_force_kerberos_conducted(path_to_attacks):
		parsed_brute_force_kerberos_logs = parse_brute_force_kerberos(path_to_attacks)
		relevant_data["brute_force_kerberos"] = parsed_brute_force_kerberos_logs

	return relevant_data

def parse_actions_logs(log_date_path: str) -> str:
	"""parse actions.logs file to a readable format on streamlit"""
	path_to_actions_logs = os.path.join(log_date_path, "actions.logs")

	with open(path_to_actions_logs, "r") as f:
		lines = f.readlines()
	
	# Group lines into their own lists
	logs = []
	grouped_log = ""

	for line in lines:
		if line.isspace():
			logs.append(grouped_log)
			grouped_log = ""
			continue

		line = line.strip() + "  \n"
		grouped_log += line

	parsed_logs = "\n\n".join(logs)
	return parsed_logs
