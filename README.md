# scanCheck

## Description:
The script automates the process of identifying, reading, and analyzing Nessus scan files for SOP requirements:
1.	Set Up Directories: Defines paths to directories containing scan packages and determines the current date.
2.	Define NessusScanResult Class:
  •	Initialization: Stores attributes related to Nessus scan results.
  •	Parsing Methods: Parses XML content to extract scan details such as device information, scanned ports, vulnerabilities, and scan times.
  •	Summary Method: Generates a summary of scan findings.
3.	Function check_for_new_scans(package_folders):
  •	Searches the specified directories for zip files containing today's date.
  •	Returns a list of paths to these zip files.
4.	Function read_zipped_file(zip_path):
  •	Extracts and reads the XML content from a zip file.
5.	Main Execution:
  •	Prints the directories being checked.
  •	Identifies and processes new scan files based on the current date.
  •	Extracts and parses scan results, then prints detailed findings.

## Intended Workflow:
1. The script runs periodically to check the dropbox for new scans
2. When new scans are found, the script examines the content to validate the results against SOPs
3. The script creates a .txt file in a mapped OneDrive folder
4. A Power Automate workflow monitoring the folder automatically uploads the contents of the .txt to Teams, posting the results of the script for team members to see

WIP
