#!/usr/bin/env python3

import argparse
from pprint import pprint
import whois
import json
import csv
from tqdm import tqdm
from ultra_auth import UltraApi

class CustomHelpParser(argparse.ArgumentParser):
    def print_help(self, *args, **kwargs):
        ascii_art = """
__/\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_______/\\\\\\\\\\_______/\\\\\\\\\\_____/\\\\\\__/\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\___________                    
 _\\////////////\\\\\\______/\\\\\\///\\\\\\____\\/\\\\\\\\\\\\___\\/\\\\\\_\\/\\\\\\///////////____________                   
  ___________/\\\\\\/_____/\\\\\\/__\\///\\\\\\__\\/\\\\\\/\\\\\\__\\/\\\\\\_\\/\\\\\\_______________________                  
   _________/\\\\\\/______/\\\\\\______\\//\\\\\\_\\/\\\\\\//\\\\\\_\\/\\\\\\_\\/\\\\\\\\\\\\\\\\\\\\\\_______________                 
    _______/\\\\\\/_______\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\\\//\\\\\\\\/\\\\\\_\\/\\\\\\///////________________                
     _____/\\\\\\/_________\\//\\\\\\______/\\\\\\__\\/\\\\\\_\\//\\\\\\/\\\\\\_\\/\\\\\\_______________________               
      ___/\\\\\\/____________\\///\\\\\\__/\\\\\\____\\/\\\\\\__\\//\\\\\\\\\\\\_\\/\\\\\\_______________________              
       __/\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\____\\///\\\\\\\\\\/_____\\/\\\\\\___\\//\\\\\\\\\\_\\/\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\___________             
        _\\///////////////_______\\/////_______\\///_____\\/////__\\///////////////____________            
__/\\\\\\______________/\\\\\\__/\\\\\\________/\\\\\\_______/\\\\\\\\\\_______/\\\\\\\\\\\\\\\\\\\\\\_____/\\\\\\\\\\\\\\\\\\\\\\___        
 _\\/\\\\\\_____________\\/\\\\\\_\\/\\\\\\_______\\/\\\\\\_____/\\\\\\///\\\\\\____\\/////\\\\\\///____/\\\\\\/////////\\\\\\_       
  _\\/\\\\\\_____________\\/\\\\\\_\\/\\\\\\_______\\/\\\\\\___/\\\\\\/__\\///\\\\\\______\\/\\\\\\______\\//\\\\\\______\\///__      
   _\\//\\\\\\____/\\\\\\____/\\\\\\__\\/\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\__/\\\\\\______\\//\\\\\\_____\\/\\\\\\_______\\////\\\\\\_________     
    __\\//\\\\\\__/\\\\\\\\\\__/\\\\\\___\\/\\\\\\/////////\\\\\\_\\/\\\\\\_______\\/\\\\\\_____\\/\\\\\\__________\\////\\\\\\______    
     ___\\//\\\\\\/\\\\\\/\\\\\\/\\\\\\____\\/\\\\\\_______\\/\\\\\\_\\//\\\\\\______/\\\\\\______\\/\\\\\\_____________\\////\\\\\\___   
      ____\\//\\\\\\\\\\\\//\\\\\\\\\\_____\\/\\\\\\_______\\/\\\\\\__\\///\\\\\\__/\\\\\\________\\/\\\\\\______/\\\\\\______\\//\\\\\\__  
       _____\\//\\\\\\__\\//\\\\\\______\\/\\\\\\_______\\/\\\\\\____\\///\\\\\\\\\\/______/\\\\\\\\\\\\\\\\\\\\\\_\\///\\\\\\\\\\\\\\\\\\\\\\/___ 
        ______\\///____\\///_______\\///________\\///_______\\/////_______\\///////////____\\///////////_____
 
"""
        print(ascii_art)
        super().print_help(*args, **kwargs)

def get_zones(client):
    uri = "/v3/zones"
    all_zones = []
    params = {'limit': 1000}
    while True:
        data = client.get(uri, params=params)
        all_zones.extend(data.get('zones', []))

        # Pagination
        next_cursor = data.get('cursorInfo', {}).get('next')
        if not next_cursor:
            break
        params['cursor'] = next_cursor

    return all_zones

def get_soa_record(zone_name, client):
    soa_url = f"/v3/zones/{zone_name}/rrsets/SOA/"
    data = client.get(soa_url)
    rdata = data.get('rrSets', [{}])[0].get('rdata', [''])[0]
    return rdata.split(' ')[1].replace('\\.', '.')

def get_aliased_domains(client):
    base_url = "/v3/zones/"
    params = {'q': 'zone_type:ALIAS', 'limit': 1000}
    all_aliased_domains = {}

    while True:
        data = client.get(base_url, params=params)
        all_aliased_domains.update(
            {zone['originalZoneName']: zone['properties']['name'] for zone in data.get('zones', [])}
        )

        # Pagination
        next_cursor = data.get('cursorInfo', {}).get('next')
        if not next_cursor:
            break
        params['cursor'] = next_cursor

    return all_aliased_domains

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        registrar = domain_info.registrar
        if registrar:
            registrar = registrar.encode('utf-8', 'replace').decode('utf-8')
        return registrar, expiration_date.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        return "Not found", "Not found"

def write_to_file(report, filename, format):
    if format == 'json':
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
    elif format == 'csv':
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=report[0].keys())
            writer.writeheader()
            for row in report:
                writer.writerow(row)

if __name__ == "__main__":
    parser = CustomHelpParser(description="UltraDNS Zone+WHOIS Report")

    # Group authentication arguments
    auth_group = parser.add_argument_group('authentication')
    auth_group.add_argument("-u", "--username", help="Username for authentication")
    auth_group.add_argument("-p", "--password", help="Password for authentication")
    auth_group.add_argument("-t", "--token", help="Directly pass the Bearer token")
    auth_group.add_argument("-r", "--refresh-token", help="Pass the Refresh token (optional with --token)")
    
    parser.add_argument("-o", "--output-file", type=str, help="Output file for storing the data.")
    parser.add_argument("-f", "--format", type=str, choices=["json", "csv"], default="json", help="Format for output file: json or csv.")

    args = parser.parse_args()

    # Enforce the rules specified
    if args.token:
        if args.username or args.password:
            parser.error("You cannot provide a token along with a username or password.")
    elif args.username and args.password:
        pass
    elif args.username or args.password:  # If one of them is provided but not both
        parser.error("You must provide both a username and password.")
    else:
        parser.error("You must provide either a token, or both a username and password.")
    
    if args.token:
        client = UltraApi(args.token, args.refresh_token, True)
    else:
        client = UltraApi(args.username, args.password)

    zones = get_zones(client)
    aliased_domains_map = get_aliased_domains(client)

    report = []

    for zone in tqdm(zones, desc="Processing Zones", ncols=100):
        zone_name = zone['properties']['name'].rstrip('.')
        try:
            zone_contact_email = get_soa_record(zone_name, client)
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
        write_to_file(report, args.output_file, args.format)
    else:
        pprint(report)
