#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor 
from urllib.parse import urlparse
import shutil
import requests
import yaml
import json
import re

# Have fun :)

class AssetMonitor:
    def __init__(self):
            self.domains, self.path, self.screenshots, self.hackerone_programs, self.hackerone_update_scope, self.workers, self.discord_enabled = self.parsing_args()
            self.hackerone_username, self.hackerone_api, self.discord_webhook = self.parse_yaml_config()

    def parse_yaml_config(self):
        config_dir = Path.home() / '.config' / 'assetmonitor'
        config_file = Path.home() / '.config' / 'assetmonitor' / 'config.yaml'

        default_config = {
            "hackerone-username": "",
            "hackerone-api": "",
            "discord-webhook": ""
        }

        if not config_file.exists():
            print(f"Creating config.yaml at {config_dir}")
            config_dir.mkdir(parents=True, exist_ok=True)
            try:
                with open(config_file, 'w') as f:
                    yaml.dump(default_config, f)
                    print(f"Config file created at {config_file}")
            except Exception as e:
                print(f"Error creating config file: {e}")
        else:
            print(f"Config file found at {config_file}.")

        with open(config_file) as stream:
            try:
                yaml_config = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit(1)

        hackerone_username = yaml_config.get("hackerone-username", "")
        hackerone_api = yaml_config.get("hackerone-api", "")
        discord_webhook = yaml_config.get("discord-webhook", "")

        if self.discord_enabled and not discord_webhook:
            print("Discord webhook URL is not set in the config file.")
            sys.exit(1)

        if (self.hackerone_programs or self.hackerone_update_scope) and (not hackerone_username or not hackerone_api):
            print("HackerOne credentials are not set in the config file.")
            sys.exit(1)

        return hackerone_username, hackerone_api, discord_webhook
        
    def hackerone_fetch_scope(self, program):
        directory_path = self.path or "assetmonitor"
        base_path = Path(directory_path) 

        if len(self.hackerone_username) == 0 and len(self.hackerone_api) == 0:
            print("Empty hackerone credentials in config")
            sys.exit(1)
        output_file = Path(base_path) / f"hackerone_{program}_scope.json"
        
        # fetch scope data and save to output_file if first time or --update option active
        if not os.path.exists(output_file) or self.hackerone_update_scope: 
            if not os.path.exists(output_file):
                base_path.mkdir(parents=True, exist_ok=True)

            print(f"Fetching files using api for program {program}")
            url = f"https://api.hackerone.com/v1/hackers/programs/{program}/structured_scopes"
            auth = (self.hackerone_username, self.hackerone_api)
            headers = {'Accept': 'application/json'}

            try:
                response = requests.get(url, auth=auth, headers=headers, timeout=15)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"Error fetching HackerOne scope for program {program}: {e}")
                print("Make sure you have correct credentials in config.yaml.")
                sys.exit(1)

            data = response.json()

            try:
                with open(output_file, "w") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print(f"Error saving file for {program}: {e}")

        # try to load the output_file
        try: 
            with open(output_file, "r") as f:
                data = json.load(f) 
        except Exception as e:
            print(f"Error loading program scope from file: {e}")
            sys.exit(1)

        # regex for https://*.example.com type wildcards
        for asset in data["data"]:
            if asset["attributes"]["eligible_for_bounty"] == True and (asset["attributes"]["asset_type"] == "WILDCARD" or asset["attributes"]["asset_type"] == "URL"):
                wildcard_asset = asset["attributes"]["asset_identifier"]
                pattern = re.search(r'^(?:https?:\/\/)?\*\..*', wildcard_asset)
                if pattern:
                    if wildcard_asset.startswith("http"):
                        domain_wildcard = urlparse(pattern.group(0)).netloc
                    else:
                        domain_wildcard = pattern.group(0) 

                    if domain_wildcard.startswith("*."):
                        self.domains.append(domain_wildcard[2:])
                    else:
                        self.domains.append(domain_wildcard)

        self.domains = remove_dupes(self.domains)

    def parsing_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-d', '--domain', help='Domain to enumerate')
        parser.add_argument('-o', '--output', help='Output directory (default assetmonitor)',)
        parser.add_argument('-l', '--list', help='File containing list of domains')
        parser.add_argument('-ss', '--screenshots', help='Take screenshots of alive subdomains using a headless browser from HTTPX', action='store_true')
        parser.add_argument('-h1', '--hackerone', help='File containing names of hackerone programs to monitor')
        parser.add_argument('-h1p', '--hackeroneprogram', help='Single HackerOne program to monitor')
        parser.add_argument('-u', '--update', help='Update hackerone assets scope from loaded file', action='store_true')
        parser.add_argument('-w', '--workers', type=int, default=5, help='Number of concurrent workers (default 5)')
        parser.add_argument('-dc', '--discord', action='store_true', help='Enable Discord notifications via webhooks')
        
        args = parser.parse_args()


        domains = []

        if args.list:
            with open(args.list) as f:
                domains.extend([line.strip() for line in f if line.strip()])

        if args.domain:
            domains.append(args.domain.strip())
            
        # if no assets are given, print help and exit
        if not domains and not (args.hackerone or args.hackeroneprogram):
            parser.print_help()
            print("No domains or hackerone programs given.")
            sys.exit(1)

        domains = remove_dupes(domains)

        hackerone_programs = []

        if args.hackerone:
            with open(args.hackerone) as f:
                hackerone_programs.extend([line.strip() for line in f if line.strip()])

        if args.hackeroneprogram:
            hackerone_programs.append(args.hackeroneprogram.strip())

        hackerone_programs = remove_dupes(hackerone_programs)
        hackerone_update_scope = args.update
            
        return domains, args.output, args.screenshots, hackerone_programs, hackerone_update_scope, args.workers, args.discord

    def extract_domain(self, url):
        return urlparse(url.strip()).netloc or url.strip()

    def run_subfinder(self, domain, base_path):

        subfinder_path = shutil.which("subfinder")

        if not subfinder_path:
            print("Error: subfinder not detected.")
            sys.exit(1)

        try:
            if not os.path.exists(f"{base_path}/subdomains.txt"):
                # first scan
                print(f"[-] First subfinder scan on {domain}")

                subprocess.run([subfinder_path, "-all", "-d", domain, "-o", f"{base_path}/subdomains.txt"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
                shutil.copy(f"{base_path}/subdomains.txt", f"{base_path}/newsubdomains.txt")
                print(f"[-] It is a first scan on {domain} to create basic files, to monitor assets run program again")
            else:
                # second and further scans
                print(f"[-] Running subfinder on {domain}")
                subprocess.run([subfinder_path, "-all", "-d", domain, "-o", f"{base_path}/newsubdomains.txt"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
        except subprocess.CalledProcessError as e:
            print(f"subfinder failed on {domain} with error: {e}")
        except Exception as e:
            print(f"Error running subfinder on {domain}: {e}")

    def check_diff(self, base_path):
        newsubdomains_file = Path(base_path) / "newsubdomains.txt"
        subdomains_file = Path(base_path) / "subdomains.txt"
        diff_file = Path(base_path) / "diff.txt"

        # load files into sets
        try:
            with open(newsubdomains_file) as f:
                newsubdomains = set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"{newsubdomains_file} not found.")
            return False

        try:
            with open(subdomains_file) as f:
                existing_subdomains = set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            existing_subdomains = set()

        # find new domains
        new_entries = newsubdomains - existing_subdomains

        # save diff.txt
        with open(diff_file, "w") as f:
            for sub in sorted(new_entries):
                f.write(sub + "\n")

        newsubdomains = remove_dupes(newsubdomains)
        # save sorted and filtered newsubdomains
        with open(newsubdomains_file, "w") as f:
            for sub in sorted(newsubdomains):
                f.write(sub + "\n")

        # append new domains that were found 
        with open(subdomains_file, "a") as f:
            for sub in sorted(new_entries):
                f.write(sub + "\n")

        return len(new_entries) > 0

    def final_results(self, domain, base_path):

        httpx_path = shutil.which("httpx")

        if not httpx_path:
            print("Error: httpx not detected.")
            sys.exit(1)

        print(f"[-] Running httpx on {domain}")

        diff_file = Path(base_path) / "diff.txt"
        httpx_output = Path(base_path) / "newsubdomains_httpx.txt"

        summary_output_file = Path(base_path) / "summary.txt"

        if self.screenshots: 
            print(f"Screenshots enabled. It might take a while if you do not have a headless browser installed.") 

        # run httpx with --screenshots option or without to check alive subdomains
        try:
            with open(httpx_output, "w") as outfile:
                result_httpx = subprocess.run(
                        [httpx_path, "-l", str(diff_file), "-ss"] if self.screenshots else [httpx_path, "-l", str(diff_file)],
                        stdout=outfile,
                        stderr=subprocess.PIPE
                        )
            if result_httpx.returncode != 0:
                print("httpx error:", result_httpx.stderr.decode())
        except subprocess.CalledProcessError as e:
            print(f"httpx failed for {domain} with error: {e}")
        except subprocess.TimeoutExpired:
            print(f"httpx timed out for {domain}!")
        except Exception as e:
            print(f"Error running httpx for {domain}: {e}")

        with open(diff_file, 'r') as f:
            output_subfinder = f.read()

        with open(httpx_output, 'r') as f:
            output_httpx = f.read()

        discord_message = f"""
{domain} - change in assets ⚠️

Subfinder:
{output_subfinder}

        """

        httpx_not_empty = os.path.getsize(httpx_output) > 0

        if httpx_not_empty:
            discord_message += f"""
HTTPX:
{output_httpx}
        
        """
        else:
            discord_message += """
HTTPX found no new alive subdomains.
        """
        
        # handle sending output to Discord and saving summary file
        if self.screenshots and httpx_not_empty:
            screenshots_before_dir = Path("output")

            if not screenshots_before_dir.exists():
                if self.discord_enabled: 
                    discord_response = requests.post(self.discord_webhook, data={"content": discord_message})
                    if not discord_response.ok:
                        print(f"Error sending to Discord: {discord_response.status_code}")

                print("Screenshots directory not found.")

                with open(summary_output_file, "w") as summary:
                   summary.write(discord_message)
                    
                print(discord_message)
                print(f"Summary file for {domain} has been saved at: {summary_output_file}")

                sys.exit(1) 

            screenshots_dir = Path(base_path) / "output"

            shutil.move(str(screenshots_before_dir), str(screenshots_dir))

            gztar_path = Path(base_path) / f"{domain}_screenshots"

            shutil.make_archive(gztar_path, 'gztar', screenshots_dir)

            if self.discord_enabled:
                discord_response = requests.post(self.discord_webhook, data={"content": discord_message}, files={"file": open(f"{gztar_path}.tar.gz", "rb")})
                if not discord_response.ok:
                    print(f"Error sending to Discord: {discord_response.status_code}")

            with open(summary_output_file, "w") as summary:
               summary.write(discord_message)
            print(discord_message)
            print(f"Summary file for {domain} has been saved at: {summary_output_file}")
        else:
            if self.discord_enabled:
                discord_response = requests.post(self.discord_webhook, data={"content": discord_message})
                if not discord_response.ok:
                    print(f"Error sending to Discord: {discord_response.status_code}")

            with open(summary_output_file, "w") as summary:
                summary.write(discord_message)
            print(discord_message)
            print(f"Summary file for {domain} has been saved at: {summary_output_file}")

    def monitor_domain(self, domain):
        # monitoring a single domain one by one
        try:
            domain = self.extract_domain(domain)
            print(f"Monitoring domain: {domain}")
            directory_path = self.path or "assetmonitor"
            base_path = Path(directory_path) / domain
            
            if not base_path.exists():
                base_path.mkdir(parents=True, exist_ok=True)

            self.run_subfinder(domain, base_path)
            changes = self.check_diff(base_path)

            if changes:
                self.final_results(domain, base_path)
            else:
                print("No new subdomains found for", domain)
        except Exception as e:
            print(f"Error monitoring {domain}: {e}")

    def run(self):
        if not shutil.which("subfinder") or not shutil.which("httpx"):
            print("Install subfinder and httpx.")

        # if hackerone programs are provided, fetch their scopes
        for program in self.hackerone_programs:
            self.hackerone_fetch_scope(program)

        self.domains = remove_dupes(self.domains)

        # if domains are provided, monitor them using workers
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            executor.map(self.monitor_domain, self.domains)

def remove_dupes(items):
    return list(set(item.lower() for item in items))

if __name__ == "__main__":
    monitor = AssetMonitor()
    monitor.run()
