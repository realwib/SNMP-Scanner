from pysnmp.hlapi import *
import json
import logging
import ipaddress

# Define OIDs with their categories and features
oid_map = {
    '1.3.6.1.2.1.1.1.0': {'category': 'System Management', 'feature': 'System Description'},
    '1.3.6.1.2.1.1.5.0': {'category': 'System Management', 'feature': 'System Name'},
    '1.3.6.1.2.1.1.6.0': {'category': 'System Management', 'feature': 'System Location'},
    '1.3.6.1.2.1.1.4.0': {'category': 'System Management', 'feature': 'System Contact'},
    '1.3.6.1.2.1.2.2.1.1': {'category': 'Interface Management', 'feature': 'Interface Index'},
    '1.3.6.1.2.1.2.2.1.2': {'category': 'Interface Management', 'feature': 'Interface Description'},
    '1.3.6.1.2.1.2.2.1.5': {'category': 'Interface Management', 'feature': 'Interface Speed'},
    '1.3.6.1.2.1.2.2.1.7': {'category': 'Interface Management', 'feature': 'Interface Admin Status'},
    '1.3.6.1.2.1.2.2.1.8': {'category': 'Interface Management', 'feature': 'Interface Oper Status'},
    '1.3.6.1.2.1.2.2.1.10': {'category': 'System Performance', 'feature': 'Interface In Octets'},
    '1.3.6.1.2.1.2.2.1.16': {'category': 'System Performance', 'feature': 'Interface Out Octets'},
    '1.3.6.1.2.1.2.2.1.13': {'category': 'Network Statistics', 'feature': 'Interface In Errors'},
    '1.3.6.1.2.1.2.2.1.14': {'category': 'Network Statistics', 'feature': 'Interface Out Errors'},
    '1.3.6.1.2.1.25.2.3': {'category': 'System Performance', 'feature': 'Disk Usage'},
    '1.3.6.1.2.1.25.1.1': {'category': 'System Performance', 'feature': 'System Up Time'},
    '1.3.6.1.2.1.25.1.2': {'category': 'System Performance', 'feature': 'Memory Usage'},
}

# Community strings to test
community_strings = ['hashinc', 'public']  # Add more community strings as needed

# Set up logging
logging.basicConfig(filename='snmp_scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_ip(ip, community, version):
    """Perform SNMP scan on a given IP address with the specified community and SNMP version."""
    results = {category: {} for category in set(value['category'] for value in oid_map.values())}
    has_data = False
    
    for oid, info in oid_map.items():
        try:
            error_indication, error_status, error_index, var_binds = next(
                nextCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=version-1),
                    UdpTransportTarget((ip, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicallySorted=True,
                    timeout=10,
                    maxRepetitions=10,
                )
            )
            
            if error_indication:
                logging.error(f'{ip} - Community: {community}, SNMP v{version} - Error: {error_indication}')
                continue
            if error_status:
                logging.error(f'{ip} - Community: {community}, SNMP v{version} - Error: {error_status.prettyPrint()}')
                continue

            for var_bind in var_binds:
                oid_value = var_bind[1].prettyPrint()
                category = info['category']
                feature = info['feature']
                results[category][feature] = oid_value
                has_data = True

                # Log detailed information
                logging.info(f'{ip} - Community: {community}, SNMP v{version}, OID: {oid} - Data: {oid_value}')
        
        except Exception as e:
            logging.error(f'{ip} - Community: {community}, SNMP v{version} - Exception: {str(e)}')

    if not has_data:
        logging.info(f'{ip} - Community: {community}, SNMP v{version} - No response received')

    return results

def main():
    start_ip = ipaddress.IPv4Address('10.0.0.1')
    end_ip = ipaddress.IPv4Address('10.0.0.2')  # Adjust end IP as needed
    version_list = [1, 2]  # SNMP versions
    output = {}

    for ip in ipaddress.IPv4Network(f'{start_ip}/24', strict=False):
        if ip < start_ip or ip > end_ip:
            continue

        ip_str = str(ip)
        print(f"Scanning {ip_str}...")
        ip_results = {}

        for version in version_list:
            for community in community_strings:
                print(f"Trying {community} with SNMP v{version}...")
                result = scan_ip(ip_str, community, version)
                
                # Include only non-empty results
                if any(result.values()):  # Check if there is any data
                    ip_results[f"SNMPv{version}_{community}"] = result
                else:
                    # Log the case where there was no response
                    logging.info(f'{ip_str} - Community: {community}, SNMP v{version} - No data available')

        if ip_results:
            output[ip_str] = ip_results

    # Save results to a JSON file
    with open('snmp_scan_results.json', 'w') as f:
        json.dump(output, f, indent=4)

    print("Scan complete. Results saved to 'snmp_scan_results.json'.")

if __name__ == '__main__':
    main()
