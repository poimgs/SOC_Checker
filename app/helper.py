from datetime import datetime
from typing import Union
import os

# Path to logs
LOGS_PATH = os.path.join("app", "logs")

def date_exists(date: datetime) -> Union[str,None]:
	"""Checks if date exists in logs folder"""
	parsed_date = date.strftime("%d%m%y")
	log_date_path = os.path.join(LOGS_PATH, parsed_date)

	if os.path.isdir(log_date_path):
		return log_date_path

	return None

def get_ip_type(ip: str) -> str:
	"""Get type of IP (IP address/network)"""
	if "/" in ip:
		return "network"

	return "ip_address"

def scans_folder_exists(log_date_path: str, ip: str) -> tuple[Union[str,None],str]:
	"""Checks if scans folder exists in logs directory"""
	path_to_ip = os.path.join(log_date_path, ip.replace("/", "_"))
	path_to_scans = os.path.join(path_to_ip, "scans")

	ip_contents = os.listdir(path_to_ip)

	if "scans" in ip_contents and "/" in ip:
		return "network", path_to_scans

	if "scans" in ip_contents:
		return "ip_address", path_to_scans

	return None, None

def attacks_folder_exists(log_date_path: str, ip: str) -> str:
	"""Checks if attacks folder exists in logs directory"""
	path_to_ip = os.path.join(log_date_path, ip.replace("/", "_"))
	path_to_attacks = os.path.join(path_to_ip, "attacks")

	ip_contents = os.listdir(path_to_ip)

	if "attacks" in ip_contents:
		return path_to_attacks

	return None

def brute_force_SSH_conducted(path_to_attacks: str):
	"""Check if brute force attack done in attacks folder"""
	attacks_directory_contents = os.listdir(path_to_attacks)
	return "brute_force_SSH.txt" in attacks_directory_contents

def brute_force_kerberos_conducted(path_to_attacks: str):
	"""Check if brute force attack done in attacks folder"""
	attacks_directory_contents = os.listdir(path_to_attacks)
	return "brute_force_kerberos.txt" in attacks_directory_contents
