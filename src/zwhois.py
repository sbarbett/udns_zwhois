import argparse
import requests
from pprint import pprint
import whois
import json
import csv

def get_ultradns_access_token(username, password):
    token_url = "https://api.ultradns.com/authorization/token"
    data = {
        'grant_type': 'password',
        'username': username,
        'password': password
    }
    response = requests.post(token_url, data=data)
    response.raise_for_status()
    token_data = response.json()
    return token_data.get('accessToken')

def get_zones(token):
    zones_url = "https://api.ultradns.com/v2/zones"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(zones_url, headers=headers)
    response.raise_for_status()
    return response.json().get('zones', [])

def get_soa_record(zone_name, token):
    soa_url = f"https://api.ultradns.com/v2/zones/{zone_name}/rrsets/SOA/"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(soa_url, headers=headers)
    response.raise_for_status()
    rdata = response.json().get('rrSets', [{}])[0].get('rdata', [''])[0]
    return rdata.split(' ')[1].replace('\\.', '.')

def get_aliased_domains(token):
    alias_url = "https://api.ultradns.com/v2/zones/?q=zone_type:ALIAS&limit=1000"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(alias_url, headers=headers)
    response.raise_for_status()
    return {zone['originalZoneName']: zone['properties']['name'] for zone in response.json().get('zones', [])}

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        return domain_info.registrar, expiration_date.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        return "Not found", "Not found"

def write_to_file(report, filename, format):
    if format == 'json':
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
    elif format == 'csv':
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=report[0].keys())
            writer.writeheader()
            for row in report:
                writer.writerow(row)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fetch Zone and WHOIS properties from UltraDNS.')
    parser.add_argument('--username', type=str, help='Username for UltraDNS API.')
    parser.add_argument('--password', type=str, help='Password for UltraDNS API.')
    parser.add_argument('--token', type=str, help='Bearer token for UltraDNS API.')
    parser.add_argument('--output-file', type=str, help='Output file for storing the data.')
    parser.add_argument('--format', type=str, choices=['json', 'csv'], default='json', help='Format for output file: json or csv.')

    args = parser.parse_args()

    # Check if format is provided without output-file
    if args.format != 'json' and not args.output_file:
        parser.error("The --format option requires the --output-file option to be set.")

    if args.token:
        token = args.token
    elif args.username and args.password:
        token = get_ultradns_access_token(args.username, args.password)
    else:
        parser.error("You must provide either a username and password or a bearer token.")

    zones = get_zones(token)
    aliased_domains_map = get_aliased_domains(token)

    report = []
    
    for zone in zones:
        zone_name = zone['properties']['name'].rstrip('.')
        zone_contact_email = get_soa_record(zone_name, token)
        alias = aliased_domains_map.get(zone_name, None)
        registrar, expiration_date = get_whois_info(zone_name)

        report.append({
            "Domain Name": zone_name,
            "Last Modified": zone['properties']['lastModifiedDateTime'],
            "Zone Contact E-Mail": zone_contact_email,
            "Registrar": registrar,
            "Domain Expiration": expiration_date,
            "Aliased Domains": alias,
            "Zone Type": zone['properties']['type'],
            "Resource Record Count": zone['properties']['resourceRecordCount']
        })
    
    if args.output_file:
        if args.format:
            write_to_file(report, args.output_file, args.format)
        else:
            parser.error("You must specify a format (json or csv) when providing an output file.")
    else:
        pprint(report)