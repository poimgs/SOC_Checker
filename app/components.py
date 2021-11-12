import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime
from typing import Union
import os
import process_data
import helper

# CONFIG COMPONENTS
def config() -> None:
	"""Sets default configuration for streamlit page"""
	st.set_page_config(
		page_title="SOC Checker Analysis",
		layout="wide",
		initial_sidebar_state="collapsed",
		menu_items={
			"About": "Made with love by [Steven Chia](https://github.com/poimgs)",
		}
	)

# STATIC COMPONENTS
def horizontal_line() -> None:
	"""Simple horizontal line to split page into different sections"""
	st.write("----------------------------------")

def side_bar() -> None:
	"""Side bar component to show guide to use SOChecker.sh"""
	st.sidebar.write("# Guide to use SOChecker")
	st.sidebar.write("On your terminal in the project's root directory:")

	st.sidebar.write("**Install required dependencies**  ")
	st.sidebar.code("sudo bash SOChecker.sh install  ")

	st.sidebar.write("**Scan a network (CIDR format) or an IP address**  ")
	st.sidebar.code("sudo bash SOChecker.sh scan")

	st.sidebar.write("**Conduct an attack on a target IP address**  ")
	st.sidebar.code("sudo bash SOChecker.sh attack")

	st.sidebar.write("# How the Web Application works")
	st.sidebar.write("- Any scan and attack you conduct will be saved in the logs folder")
	st.sidebar.write("- This web app uses your logs to populate information")
	st.sidebar.write("- The more you use SOChecker.sh, the more information you get to play with!")
	st.sidebar.write("**Made with love by Steven**")
	st.sidebar.write("[Link to Github page](https://github.com/poimgs/SOC_Checker)")

def header() -> None:
	"""Header for streamlit page"""
	st.write("# SOC Checker (Analysis)")

# SELECTOR COMPONENTS
def date_selector() -> None:
	"""Simple date selector to allow user to choose date of logs to analyse"""
	date = st.date_input("Date Selector")
	return date

def target_picker(log_date_path: Union[str,None], date: datetime) -> str:
	"""Asks user for target to analyse""" 

	# if date cannot be found, return an error message
	if log_date_path is None:
		st.warning(f"""
We could not find any logs for the date of {date}  \n
Please select another date.
""")

		st.info(f"""
If you are a new user, click on the arrow located at the top-left of the screen.  \n
You will find a mini guide that will help you use this program
""")
		return

	# Get targets in directory and create a target selector
	targets_found = process_data.get_targets(log_date_path)

	st.info("""
		You have conducted scans/attacks on the following targets.  \n
		Choose the target you want to analyse below
		""")

	selected_ip = st.selectbox("IP/Network", targets_found)
	return selected_ip

# OUTPUT ANALYSIS COMPONENTS
def network_analysis(log_date_path: str, ip: str) -> None:
	"""Show network analysis output"""
	_, path_to_scans = helper.scans_folder_exists(log_date_path, ip)
	path_to_attacks = helper.attacks_folder_exists(log_date_path, ip)

	# Get scans logs information
	transformed_scan_logs = scans_analyser(log_date_path, ip)

	# Show general information
	st.write("## General Information")

	host_df, port_df = transformed_scan_logs["network"]

	# Show filters
	filter_left, filter_right = st.columns(2)

	# Populate OS filter
	os_filter_contents = ["All"]
	os_in_df = host_df["os_name"].dropna().unique()

	if len(os_in_df) > 0:
		os_filter_contents.extend(os_in_df)
	
	selected_OS = filter_left.selectbox("OS types", os_filter_contents)

	# Populate port filter
	port_filter_contents = ["All"]
	ports_in_df = sorted(port_df["number"].unique().astype(int))
	port_filter_contents.extend(ports_in_df)

	selected_port = filter_right.selectbox("Ports", port_filter_contents)

	# Filter dataframes based on filters
	if selected_OS != "All":

		# Filter host df by os name
		host_df = host_df[host_df["os_name"] == selected_OS]
		
		# Filter port df by ips in filtered host df
		host_ips = host_df["ip"].values
		port_df = port_df[port_df["ip"].isin(host_ips)]

	if selected_port != "All":

		# Filter port df by port
		port_df = port_df[port_df["number"] == selected_port]

		# Filter host df byips in filtered port df
		port_ips = port_df["ip"].values
		host_df = host_df[host_df["ip"].isin(port_ips)]		

	# Sort port_df so that the heatmap chart looks better!
	port_df = port_df.sort_values(by="number")

	# Get key metrics from dataframes
	number_hosts = len(host_df)
	number_host_ports_open = len(port_df["ip"].unique())
	number_windows_hosts = len(host_df[host_df["os_name"] == "windows"])
	number_linux_hosts = len(host_df[host_df["os_name"] == "linux"])
	
	metric_first_col, metric_second_col, metric_third_col, metric_fourth_col = st.columns(4)

	metric_first_col.metric("Total Hosts", number_hosts)
	metric_second_col.metric("Total Hosts with ports open", number_host_ports_open)
	metric_third_col.metric("Windows Hosts", number_windows_hosts)
	metric_fourth_col.metric("Linux Hosts", number_linux_hosts)

	# Provide more information for host and ip info
	info_left_col, info_right_col = st.columns(2)

	# Get port information for each host
	if selected_OS == "All":
		selected_OS_ip_list = host_df["ip"].values
	else:
		selected_OS_ip_list = host_df[host_df["os_name"] == selected_OS]["ip"].values

	# Create and output string for port information for IP focused information
	ip_focused_info = "### IP-focused information  \n\n"

	for ip in selected_OS_ip_list:
		ports_info = port_df[port_df["ip"] == ip][["number", "service", "transport_protocol"]]
		ports_number_list = ports_info["number"].values 
		service_number_list = ports_info["service"].values
		transport_protocol_list = ports_info["transport_protocol"].values

		ip_focused_info += f"**{ip}**  \n\n"
		
		for port, service, transport_protocol in zip(ports_number_list, service_number_list, transport_protocol_list):
			if service is not None:
				ip_focused_info += f"> {port}/{transport_protocol}: {service}  \n"
			else:
				ip_focused_info += f"> {port}/{transport_protocol}  \n"

		ip_focused_info += "\n"

	info_left_col.write(ip_focused_info)

	# Get ip information based on open ports
	if selected_port == "All":
		selected_port_ip_list = sorted(port_df["ip"].unique())
	else:
		selected_port_ip_list = sorted(port_df[port_df["number"] == selected_port]["ip"].unique())

	# Create and outpiut string for ip information for Port focused information
	port_focused_info = "### Port-focused information  \n\n"

	if selected_port != "All":
		port_focused_info += f"**IP Addresses with port {selected_port} open**  \n\n"
	else:
		port_focused_info += "**IP Addresses with any port open**  \n\n"

	for ip in selected_port_ip_list:
		port_focused_info += f"> - {ip}  \n"

	info_right_col.write(port_focused_info)

	# Allow user to also see data in tabular format
	st.write("\n")
	with st.expander("Data in tabular form"):
		host_col, port_col = st.columns(2)

		host_col.write("### Host information")
		host_col.table(host_df)

		port_col.write("### Port infomation")
		port_col.table(port_df)


	horizontal_line()

	# Show specific information for individual IP address
	st.write("## IP specific information")

	# Transform scan logs into dictionary to easily access information
	del transformed_scan_logs["network"]
	ip_addresses = transformed_scan_logs.keys()
	selected_ip = st.selectbox("Analyse an ip", transformed_scan_logs, help="Information shown only pertains to scan done on network.  \nFor more information, select on the specific IP above")

	st.write(transformed_scan_logs[selected_ip])

def ip_analysis(log_date_path: str, ip: str) -> None:
	"""Show ip address analysis output"""
	_, path_to_scans = helper.scans_folder_exists(log_date_path, ip)
	path_to_attacks = helper.attacks_folder_exists(log_date_path, ip)

	if path_to_scans and path_to_attacks:
		# Create a column for scan and another for attacks logs
		scans_column, attacks_column = st.columns(2)

		# Get logs information
		transformed_scan_logs = scans_analyser(log_date_path, ip)
		transformed_attack_logs = attacks_analyser(log_date_path, ip)

		attacks_conducted = transformed_attack_logs.keys()

		# Populate scans column
		scans_column.write("## Scan logs")
		scans_column.write(transformed_scan_logs)

		# Populate attacks column
		attacks_column.write("## Attack logs")

		# Only show selectbox if more than one attack was conducted
		if len(attacks_conducted) > 1:
			attack_chosen = attacks_column.selectbox("Attacks conducted", attacks_conducted)
			attacks_column.write(transformed_attack_logs[attack_chosen])
		else:
			attacks_column.write(list(transformed_attack_logs.values())[0])

	if path_to_scans and not path_to_attacks:
		# Get logs information
		transformed_scan_logs = scans_analyser(log_date_path, ip)

		# Populate scans logs
		st.write("## Scan logs")
		st.write(transformed_scan_logs)

	if path_to_attacks and not path_to_scans:
		# Get logs information
		transformed_attack_logs = attacks_analyser(log_date_path, ip)
		attacks_conducted = transformed_attack_logs.keys()

		# Populate attacks column
		st.write("## Attack logs")

		# Only show selectbox if more than one attack was conducted
		if len(attacks_conducted) > 1:
			attack_chosen = st.selectbox("Attacks conducted", attacks_conducted)
			st.write(transformed_attack_logs[attack_chosen])
		else:
			st.write(list(transformed_attack_logs.values())[0])

def scans_analyser(log_date_path: str, ip: str) -> Union[str,dict]:
	"""Show results of scans done by user"""

	def transform_parsed_scan_logs_IP(host_information: dict, scan_type: str) -> str:
		"""Transform parsed scan logs dictionary into string for streamlit"""
		output_str = f"""
### IP Information

> Status: {host_information["host_state"]}

"""

		if host_information["OS_name"] is not None:
			output_str += f"> OS: {host_information['OS_name']} (Probability: {host_information['OS_accuracy']}%)  \n"

		if host_information["mac_address"] is not None:
			output_str += f"> Mac Address: {host_information['mac_address']} ({host_information['mac_address_vendor']})"

		if host_information["ports"] is not None:
			output_str += f"""

### Ports Open

"""
			for port in host_information["ports"]:
				output_str += f"""
**Port Number: {port['number']} ({port['transport_protocol']})**

> State: {port['state']}  \n
"""

				if port["service"] is not None:
					output_str += f"> Service: {port['service']}  \n"

				if port["product"] is not None:
					output_str += f"> Product: {port['product']}"

				if port["version"] is not None:
					output_str += f" ({port['version']})"

				output_str += "\n\n"

		else:
			output_str += f"""

### **No ports open**  \n
"""

		output_str += "### Additional Information \n"

		if scan_type == "nmap_aggressive":
			output_str += f"Scan was run using nmap -A -Pn -p- {ip}  \n\n"

		if scan_type == "nmap_silent":
			output_str += f"Scan was run using nmap -sS -Pn -p- {ip}  \n\n"
			output_str += "**Note**: To get more information, run nmap AGGRESSIVELY"

		if scan_type == "masscan":
			output_str += f"Scan was run using masscan {ip} -p0-65535 --ports U:0-65535 --rate=100000  \n\n"
			output_str += "**Note**: To get more information, run nmap (preferably AGGRESSIVELY)"

		return output_str

	def transform_parsed_scan_logs_network(parsed_scan_logs: dict, scan_type: str) -> pd.DataFrame:
		"""Transform parsed scan logs for network into dataframe for easier filtering by streamlit"""

		host_dict = {
			"ip": [],
			"os_name": []
		}

		port_dict = {
			"ip": [],
			"number": [],
			"transport_protocol": [],
			"service": []
		}

		# Extract host information from parsed scan logs
		for ip, host_information in parsed_scan_logs.items():
			if host_information["OS_name"] is not None:
				if "linux" in host_information["OS_name"].lower():
					os_name = "linux"
				elif "windows" in host_information["OS_name"].lower():
					os_name = "windows"
				else:
					os_name = None
			else:
				os_name = None

			host_dict["ip"].append(ip)
			host_dict["os_name"].append(os_name)

			# Extract port information from parsed scan logs
			if host_information["ports"] is not None:
				for port in host_information["ports"]:
					port_number = port["number"]

					if port["service"] is not None:
						port_service = port["service"]
					else:
						port_service = None

					if port["transport_protocol"] is not None:
						transport_protocol = port["transport_protocol"]
					else:
						transport_protocol = None

					port_dict["ip"].append(ip)
					port_dict["number"].append(port_number)
					port_dict["service"].append(port_service)
					port_dict["transport_protocol"].append(transport_protocol)

		# Convert dictionary into dataframes to be returned
		host_df = pd.DataFrame(host_dict)
		port_df = pd.DataFrame(port_dict)

		# Convert port number to int type
		port_df["number"] = port_df["number"].astype("int32")

		return host_df, port_df

		if scan_type == "nmap_silent" or scan_type == "masscan":
			return parsed_scan_logs

	# Start of non-helper functions
	type_of_ip, path_to_scans = helper.scans_folder_exists(log_date_path, ip)

	# Get parsed scans log data
	parsed_scan_logs, scan_type = process_data.parse_scans_logs(type_of_ip, path_to_scans)

	# Transform parsed scans logs data into a readable string and return it
	if type_of_ip == "ip_address":
		transformed_scan_logs = transform_parsed_scan_logs_IP(parsed_scan_logs, scan_type)
		return transformed_scan_logs

	# Transform parsed scans logs data into readable strings by IP/network
	if type_of_ip == "network":

		host_df, port_df = transform_parsed_scan_logs_network(parsed_scan_logs, scan_type)
		# Store strings to be outputted for every IP
		ips_to_scan_logs = {
			"network": (host_df, port_df)
		}

		# Transform parsed scans logs data into readable strings, for every IP analysed
		for ip_address, host_information in parsed_scan_logs.items():
			transformed_scan_logs = transform_parsed_scan_logs_IP(host_information, scan_type)
			ips_to_scan_logs[ip_address] = transformed_scan_logs

		return ips_to_scan_logs

def attacks_analyser(log_date_path: str, ip: str) -> None:
	"""Show results of attacks done by user"""

	def transform_parsed_brute_force_SSH_logs(parsed_brute_force_SSH_logs: list) -> str:
		"""Transform parsed brute force SSH logs dictionary into string for streamlit"""
		output_str = ""

		# Header for brute force attack
		output_str += "### Brute Force: SSH  \n\n"

		for index, log in enumerate(parsed_brute_force_SSH_logs):
			attack_number = index + 1

			# Introduce each attack
			output_str += f"**Attack {attack_number}** conducted on {log['time']} using port {log['port']}  \n\n"
			output_str += "**Credentials used**  \n"

			if log['username'] is not None:
				output_str += f"username: {log['username']}  \n"
			if log['username_list'] is not None:
				output_str += f"username_list: {log['username_list']}  \n"
			if log['password'] is not None:
				output_str += f"password: {log['password']}  \n"
			if log['password_list'] is not None:
				output_str += f"password_list: {log['password_list']}  \n"

			output_str += "\n\n"

			# Show credentials found through brute forcing
			if log["credentials"] is not None:
				output_str += "**Credentials Found**  \n\n"

				for index, credential in enumerate(log["credentials"]):
					credential_number = index + 1

					output_str += f"Credential {credential_number}  \n"
					output_str += f"login: {credential['login']}  \n"
					output_str += f"password: {credential['password']}  \n\n"
			else:
				output_str += "**No Credentials Found**  \n\n"

			if attack_number < len(parsed_brute_force_SSH_logs):
				output_str += "-------------------------  \n\n"

		return output_str

	def transform_parsed_brute_force_kerberos_logs(parsed_brute_force_kerberos_logs: list) -> str:
		"""Transform parsed brute force kerberos logs dictionary into string for streamlit"""
		output_str = ""

		# Header for kerberos attack
		output_str += "### Brute Force: Kerberos  \n\n"

		for index, log in enumerate(parsed_brute_force_kerberos_logs):
			attack_number = index + 1

			# General information on attack
			output_str += f"{log['time']} | Attack {attack_number} conducted on **{log['ip']}** through domain: **{log['domain']}**  \n\n"
			output_str += f"Usernme list used: **{log['username_list']}**  \n\n"

			# Users found through kerberos enumeration attack
			if log["users"] is not None:
				output_str += "**Users found**  \n"
				for user in log["users"]:
					output_str += f"> {user}  \n"

				output_str += "  \n\n"

			if attack_number < len(parsed_brute_force_kerberos_logs):
				output_str += "-----------------------------  \n"

		return output_str

	# Check attacks that have been done on attack logs
	path_to_attacks = os.path.join(log_date_path, ip.replace("/", "_"), "attacks")

	# Parse attacks logs data to get relevant data
	parsed_attack_logs = process_data.parse_attacks_logs(path_to_attacks)

	# Transform parsed attacks logs from dictionary into dictionary with type of attack to readable string 
	transformed_attack_logs = {}

	if parsed_attack_logs["brute_force_SSH"] is not None:
		transformed_brute_force_SSH_logs = transform_parsed_brute_force_SSH_logs(parsed_attack_logs["brute_force_SSH"])
		transformed_attack_logs["brute_force_SSH"] = transformed_brute_force_SSH_logs

	if parsed_attack_logs["brute_force_kerberos"] is not None:
		transformed_brute_force_kerberos_logs = transform_parsed_brute_force_kerberos_logs(parsed_attack_logs["brute_force_kerberos"])
		transformed_attack_logs["brute_force_kerberos"] = transformed_brute_force_kerberos_logs

	return transformed_attack_logs

def logs(log_date_path: str, date: datetime) -> None:
	"""Show logs for date selected"""
	parsed_logs = process_data.parse_actions_logs(log_date_path)
	with st.expander(f"Logs for {date}"):
		st.write(parsed_logs)
