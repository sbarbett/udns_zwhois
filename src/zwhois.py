import argparse
import requests
from pprint import pprint
import whois
import json
import csv
import time
from tqdm import tqdm

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
    return token_data.get('accessToken'), token_data.get('refreshToken'), token_data.get('expiresIn')

def refresh_ultradns_access_token(refresh_token):
    token_url = "https://api.ultradns.com/authorization/token"
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }
    response = requests.post(token_url, data=data)
    response.raise_for_status()
    token_data = response.json()
    return token_data.get('accessToken'), token_data.get('expiresIn')

def api_request(url, token, method=requests.get, headers=None, **kwargs):
    """Centralized function for making API requests. This handles token refresh and 401 errors."""
    if not headers:
        headers = {}
    headers['Authorization'] = f'Bearer {token}'
    
    response = method(url, headers=headers, **kwargs)
    if response.status_code == 401 and refresh_token:  # Token expired, try refreshing
        token, _ = refresh_ultradns_access_token(refresh_token)
        headers['Authorization'] = f'Bearer {token}'
        response = method(url, headers=headers, **kwargs)
    elif response.status_code == 401:
        raise Exception("Your bearer token has expired. The script took longer than the token's validity. Please use credentials instead.")
    
    response.raise_for_status()
    
    return response.json()

def get_zones(token):
    zones_url = "https://api.ultradns.com/v2/zones"
    all_zones = []
    params = {'limit': 1000}
    while True:
        data = api_request(zones_url, token, params=params)
        time.sleep(0.5)
        all_zones.extend(data.get('zones', []))

        # Pagination
        next_cursor = data.get('cursorInfo', {}).get('next')
        if not next_cursor:
            break
        params['cursor'] = next_cursor

    return all_zones

def get_soa_record(zone_name, token):
    soa_url = f"https://api.ultradns.com/v2/zones/{zone_name}/rrsets/SOA/"
    data = api_request(soa_url, token)
    time.sleep(0.5)
    rdata = data.get('rrSets', [{}])[0].get('rdata', [''])[0]
    return rdata.split(' ')[1].replace('\\.', '.')

def get_aliased_domains(token):
    base_url = "https://api.ultradns.com/v2/zones/"
    params = {'q': 'zone_type:ALIAS', 'limit': 1000}
    all_aliased_domains = {}

    while True:
        data = api_request(base_url, token, params=params)
        time.sleep(0.5)
        all_aliased_domains.update(
            {zone['originalZoneName']: zone['properties']['name'] for zone in data.get('zones', [])}
        )

        # Pagination
        next_cursor = data.get('cursorInfo', {}).get('next')
        if not next_cursor:
            break
        params['cursor'] = next_cursor

    return all_aliased_domains

def get_base_domain(domain):
    parts = domain.split('.')
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return domain

def get_whois_info(domain):
    try:
        base_domain = get_base_domain(domain)
        domain_info = whois.whois(base_domain)
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
        refresh_token = None  # No refresh token when provided directly
        token_expiry_time = None  # Indeterminate expiry time
    elif args.username and args.password:
        token, refresh_token, expires_in = get_ultradns_access_token(args.username, args.password)
        token_expiry_time = time.time() + expires_in  # Record the absolute expiry time
    else:
        parser.error("You must provide either a username and password or a bearer token.")

    zones = get_zones(token)
    aliased_domains_map = get_aliased_domains(token)

    report = []

# tqdm will show progress for processing zones
for zone in tqdm(zones, desc="Processing Zones", ncols=100):

    # Check if token is about to expire
    if token_expiry_time and time.time() > token_expiry_time - 10:  # 10 seconds buffer
        if not refresh_token:
            raise Exception("Operation too long. Access token expired and no refresh token available. Use credentials instead.")
        token, expires_in = refresh_ultradns_access_token(refresh_token)
        token_expiry_time = time.time() + expires_in

    zone_name = zone['properties']['name'].rstrip('.')
    try:
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
    except Exception as e:
        print(f"Error processing zone {zone_name}: {e}")
    
    if args.output_file:
        if args.format:
            write_to_file(report, args.output_file, args.format)
        else:
            parser.error("You must specify a format (json or csv) when providing an output file.")
    else:
        pprint(report)