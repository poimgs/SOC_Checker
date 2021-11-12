import streamlit as st
import components
import process_data
import helper

def main():
	components.config()
	components.side_bar()
	components.header()
	selected_date = components.date_selector()

	# If logs do not exist, stop execution
	log_date_path = helper.date_exists(selected_date)
	if log_date_path is None:
		components.target_picker(log_date_path, selected_date)
		return

	# Load selectbox to allow user to choose which IP/network to analyse
	selected_ip = components.target_picker(log_date_path, selected_date)
	ip_type = helper.get_ip_type(selected_ip)

	# Load analysis on scans and attacks differentiated by ip type
	if ip_type == "network":
		components.network_analysis(log_date_path, selected_ip)

	if ip_type == "ip_address":
		components.ip_analysis(log_date_path, selected_ip)

	# # Load analysis of scans and attacks conducted on to ip/network
	# components.scans_and_attacks_columns(log_date_path, selected_ip)
		
	components.horizontal_line()

	# Show logs file for date selected
	components.logs(log_date_path, selected_date)

if __name__ == "__main__":
	main()

