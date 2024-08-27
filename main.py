import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import os
import zipfile

formatted_date = datetime.today().strftime('%Y%m%d')

package_folders = [
    os.path.abspath(os.path.join("C:\\Users\\matts\\Desktop\\New folder", f))
    for f in os.listdir("C:\\Users\\matts\\Desktop\\New folder")
    if os.path.isdir(os.path.join("C:\\Users\\matts\\Desktop\\New folder", f))
]

class NessusScanResult:
    def __init__(self, device_name="", ip="", credentialed_scan=False, all_ports=False):
        self.device_name = device_name
        self.ip = ip
        self.credentialed_scan = credentialed_scan
        self.all_ports = all_ports
        self.plugins = set()
        self.vulns = {}
        self.feed_within_5_day = False
        self.output_dialogue = ""
        self.scan_start_time = None
        self.scan_end_time = None
        self.scan_policy_name = ""
        self.host_properties = {}

    @staticmethod
    def parse_date(date_str):
        """Parse date string to datetime object."""
        try:
            return datetime.strptime(date_str, '%Y/%m/%d %H:%M:%S')
        except ValueError:
            return None

    @staticmethod
    def from_nessus_xml_content(xml_content):
        """Parse the content of a .nessus file and return a list of NessusScanResult objects."""
        root = ET.fromstring(xml_content)
        results = []

        # Iterate over each ReportHost (each scanned device)
        for report_host in root.findall('.//ReportHost'):
            result = NessusScanResult()
            result.device_name = report_host.get('name', '')

            # Extract host properties
            host_properties = report_host.find('.//HostProperties')
            if host_properties is not None:
                for tag in host_properties:
                    result.host_properties[tag.get('name')] = tag.text
                result.ip = result.host_properties.get('host-ip', '')
                result.credentialed_scan = result.host_properties.get('Credentialed_Scan', 'false') == 'true'

            # Determine if all ports (0-65535) were scanned
            scanned_ports = set()
            for report_item in report_host.findall('.//ReportItem'):
                port = report_item.get('port')
                if port is not None:
                    scanned_ports.add(int(port))

            result.all_ports = all(port in scanned_ports for port in range(0, 65536))

            # Extract plugins and vulnerabilities
            for report_item in report_host.findall('.//ReportItem'):
                plugin_id = report_item.get('pluginID', '')
                plugin_name = report_item.get('pluginName', '')
                severity = int(report_item.get('severity', '0'))
                vuln_name = f"{plugin_id} - {plugin_name}"
                result.plugins.add(plugin_name)
                result.vulns[vuln_name] = severity

            # Scan start and end time
            result.scan_start_time = result.parse_date(result.host_properties.get('HOST_START', ''))
            result.scan_end_time = result.parse_date(result.host_properties.get('HOST_END', ''))

            # Check if the scan feed is within the last 5 days
            if result.scan_end_time:
                result.feed_within_5_day = (datetime.now() - result.scan_end_time) <= timedelta(days=5)

            # Output dialogue - Example: Generate a summary of findings
            result.output_dialogue = (f"Device {result.device_name} with IP {result.ip} had the following "
                                      f"vulnerabilities detected: {', '.join(result.vulns.keys())}")

            # Add the result object to the list of results
            results.append(result)

        return results

    def __str__(self):
        return (f"NessusScanResult(Device Name: {self.device_name}, IP: {self.ip}, "
                f"Credentialed: {self.credentialed_scan}, All Ports Scanned: {self.all_ports}, "
                f"Plugins: {self.plugins}, Vulnerabilities: {self.vulns}, Feed Recent: {self.feed_within_5_day}, "
                f"Output: {self.output_dialogue})")

def check_for_new_scans(package_folders):
    # Get today's date in yyyymmdd format
    today = datetime.today().strftime('%Y%m%d')

    # List to store paths of .zip files containing today's date
    new_scan_paths = []

    for directory in package_folders:
        print(f"Checking directory: {directory}")
        # List all items in the directory
        items = os.listdir(directory)
        for item in items:
            item_path = os.path.join(directory, item)
            print(f"Checking item: {item_path}")
            # Check if the item is a .zip file and contains today's date
            if os.path.isfile(item_path) and item.endswith('.zip') and today in item:
                print(f"Match found: {item_path}")
                new_scan_paths.append(item_path)

    return new_scan_paths

    return new_scan_paths


def read_zipped_file(zip_path):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        # Get the name of the single file in the zip archive
        nessus_file_name = zip_ref.namelist()[0]

        # Open and read the .nessus file
        with zip_ref.open(nessus_file_name) as nessus_file:
            content = nessus_file.read()
            return content


# xml_content = extract_content_from_zip_or_folder()  # Your function to extract XML content
# results = NessusScanResult.from_nessus_xml_content(xml_content)
# for result in results:
#     print(result)
print(package_folders)
new_scans = check_for_new_scans(package_folders) # list of zips

if not new_scans:
    exit()
print('checking ' + str(new_scans))
for scan in new_scans:
    print(scan)
    scan_content = read_zipped_file(scan)
    results = NessusScanResult.from_nessus_xml_content(scan_content)
    for result in results:
        print(result)


