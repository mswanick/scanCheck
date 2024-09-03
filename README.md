# scanCheck
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

WIP
