# SNMP Scanner

This repository contains a Python script for performing SNMP scans on a range of IP addresses. The script collects data from network devices using SNMP (Simple Network Management Protocol) and logs the results.

## Features

- Configurable SNMP versions and community strings.
- Scans a specified IP range.
- Logs results and errors to a file.
- Saves scan results in a JSON file with detailed OID mappings.

## Usage

1. **Clone the repository:**

    ```bash
    git clone https://github.com/realwib/SNMP-Scanner.git
    cd SNMP-Scanner
    ```

2. **Install dependencies:**

    Ensure you have `pysnmp` installed. You can install it using pip:

    ```bash
    pip install pysnmp
    ```

3. **Configure the script:**

    - **SNMP Version:** Set the SNMP versions in the `version_list` variable in the script.
    - **Community Strings:** Add or modify community strings in the `community_strings` list.
    - **IP Range:** Adjust `start_ip` and `end_ip` in the `main()` function to specify the IP range for scanning.

4. **Run the script:**

    ```bash
    python snmp_scan.py
    ```

    The script will perform scans on the specified IP range using the configured SNMP versions and community strings. It logs detailed information and saves the results in `snmp_scan_results.json`.

## OID Mapping

The script uses a predefined set of OIDs (Object Identifiers) mapped to specific features. Here is a brief overview:

- **System Management:**
  - `1.3.6.1.2.1.1.1.0`: System Description
  - `1.3.6.1.2.1.1.5.0`: System Name
  - `1.3.6.1.2.1.1.6.0`: System Location
  - `1.3.6.1.2.1.1.4.0`: System Contact

- **Interface Management:**
  - `1.3.6.1.2.1.2.2.1.1`: Interface Index
  - `1.3.6.1.2.1.2.2.1.2`: Interface Description
  - `1.3.6.1.2.1.2.2.1.5`: Interface Speed
  - `1.3.6.1.2.1.2.2.1.7`: Interface Admin Status
  - `1.3.6.1.2.1.2.2.1.8`: Interface Oper Status

- **System Performance:**
  - `1.3.6.1.2.1.25.2.3`: Disk Usage
  - `1.3.6.1.2.1.25.1.1`: System Up Time
  - `1.3.6.1.2.1.25.1.2`: Memory Usage

The results are saved in `snmp_scan_results.json` with these OIDs mapped to their corresponding features.
