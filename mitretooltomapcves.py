import requests
import re
import textwrap
import json
from rich.console import Console
from rich.table import Table
import csv

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_CVE_API_URL = "https://cveawg.mitre.org/api/cve"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITIGATION_MAPPING_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-mapping/main/mappings/technique_mitigations.json"

API_KEY = "f5fed806-6ae5-4564-85c9-55358feee9ea"
console = Console()
attack_data_cache = None  

def clean_html(raw_html):
    return re.sub(r'<.*?>', '', raw_html)


def get_cvss_from_nvd(cve_id):
    """Fetches CVSS score from NVD API."""
    try:
        headers = {
            "apiKey": API_KEY,
            "Content-Type": "application/json", 
        }

        response = requests.get(f"{NVD_API_URL}?cveId={cve_id}", headers=headers)
        response.raise_for_status()
        data = response.json()

        if "vulnerabilities" in data and data["vulnerabilities"]:
            cve_data = data["vulnerabilities"][0].get("cve", {})
            impact = cve_data.get("metrics", {})

            if "cvssMetricV31" in impact:
                cvss_info = impact["cvssMetricV31"][0]["cvssData"]
            elif "cvssMetricV30" in impact:
                cvss_info = impact["cvssMetricV30"][0]["cvssData"]
            elif "cvssMetricV2" in impact:
                cvss_info = impact["cvssMetricV2"][0]["cvssData"]
            else:
                return "N/A", "N/A"

            return cvss_info["baseScore"], cvss_info["baseSeverity"]
        return "N/A", "N/A"
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVSS score from NVD: {e}")
        return "N/A", "N/A"

def load_cve_mappings(csv_file="cve_attack_mappings.csv"):
    mappings = {}
    try:
        with open(csv_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  
            for row in reader:
                cve, technique_id = row[0], row[1]
                mappings[cve] = technique_id
    except FileNotFoundError:
        print("CSV file not found.")
    return mappings

def get_attack_data():
    """Fetches and caches MITRE ATT&CK dataset."""
    global attack_data_cache
    if attack_data_cache is None:
        try:
            response = requests.get(ATTACK_URL)
            response.raise_for_status()
            attack_data_cache = response.json().get("objects", [])
        except requests.exceptions.RequestException as e:
            print(f"Error fetching MITRE ATT&CK data: {e}")
            return []
    return attack_data_cache

def get_cve_details(cve_id):
    """Fetches CVE details and displays only the mapped MITRE ATT&CK technique IDs."""
    try:
        response = requests.get(f"{MITRE_CVE_API_URL}/{cve_id}")
        response.raise_for_status()
        cve_data = response.json()

        if "cveMetadata" not in cve_data:
            print(f"No data found for {cve_id}.")
            return

        cvss_score, severity = get_cvss_from_nvd(cve_id)

        cve_attack_mappings = load_cve_mappings()
        attack_mapping = cve_attack_mappings.get(cve_id, "")

        
        technique_ids = attack_mapping.split("; ") if attack_mapping else []

        
        raw_description = cve_data.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", "No description available")
        clean_description = clean_html(raw_description)

     
        table = Table(title=f"CVE Details & MITRE ATT&CK Mapping for {cve_id}")
        table.add_column("Field", style="bold blue")
        table.add_column("Value", style="dim")

        table.add_row("CVE ID", cve_id)
        table.add_row("CVSS Score", f"{cvss_score} ({severity})")
        table.add_row("Description", textwrap.fill(clean_description, width=80))

      
        if technique_ids:
            for idx, technique_id in enumerate(technique_ids, start=1):
                technique_url = f"https://attack.mitre.org/techniques/{technique_id}/"
                table.add_row(f"Technique {idx}", f"[{technique_id}]({technique_url})")
        else:
            table.add_row("Techniques", "No MITRE ATT&CK technique mappings found.")

        console.print(table)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE details: {e}")


def get_technique_details(technique_id, attack_data):
    """Fetch MITRE ATT&CK technique details and map them to mitigations using STIX relationships."""
    
    
    technique = None
    for obj in attack_data:
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("external_id") == technique_id:
                    technique = obj
                    break
        if technique:
            break

    if not technique:
        print(f"No technique found for ID: {technique_id}")
        return None, None, None, []

    
    technique_name = technique.get("name", "N/A")
    technique_desc = technique.get("description", "No description available.")
    technique_url = next((ref.get("url") for ref in technique.get("external_references", []) if "mitre.org" in ref.get("url", "")), "No URL available.")

   
    mitigations = []
    for relationship in attack_data:
     if (
        relationship.get("type") == "relationship" and
        relationship.get("relationship_type") == "mitigates" and
        relationship.get("target_ref") == technique.get("id") 
    ):
        mitigation_id = relationship.get("source_ref")  
        mitigation = next((obj for obj in attack_data if obj.get("id") == mitigation_id), None)
        if mitigation:
            mitigation_ref = next((ref for ref in mitigation.get("external_references", []) if "mitre.org" in ref.get("url", "")), {})
            mitigations.append({
                "id": mitigation_ref.get("external_id", "N/A"),
                "title": mitigation.get("name", "N/A"),
                "url": mitigation_ref.get("url", "No URL available.")
            })


    table = Table(title=f"Technique Details: {technique_id}")
    table.add_column("Field", style="bold blue")
    table.add_column("Value", style="dim")
    table.add_row("Name", technique_name)
    table.add_row("Description", textwrap.fill(technique_desc, width=80))
    table.add_row("MITRE URL", technique_url)

    if mitigations:
        for mitigation in mitigations:
            table.add_row("Mitigation ID", mitigation["id"])
            table.add_row("Mitigation Title", mitigation["title"])
            table.add_row("Mitigation URL", mitigation["url"])
    else:
        table.add_row("Mitigations", "No mitigations found.")

    console.print(table)
    return technique_name, technique_desc, technique_url, mitigations



def get_threat_actor_details(threat_actor_name):
    """Fetches details of a threat actor from MITRE ATT&CK."""
    attack_data = get_attack_data()
    actors = [obj for obj in attack_data if obj.get("type") == "intrusion-set" and obj.get("name", "").lower() == threat_actor_name.lower()]
    
    if not actors:
        print("No threat actor found with that name.")
        return
    
    table = Table(title=f"Threat Actor Details: {threat_actor_name}")
    table.add_column("Field", style="bold blue")
    table.add_column("Value", style="dim")
    
    for actor in actors:
        table.add_row("Name", actor.get("name", "N/A"))
        table.add_row("Description", textwrap.fill(actor.get("description", "No description available."), width=80))
        table.add_row("MITRE URL", actor.get("external_references", [{}])[0].get("url", "No URL available."))
    
    console.print(table)

def main():
    """CLI Menu"""
    cve_mappings = load_cve_mappings()
    
    while True:
        print("\nChoose an option:")
        print("1. Search by CVE")
        print("2. Search by MITRE ATT&CK technique")
        print("3. Search by Threat Actor")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ")

        if choice == "1":
            cve_id = input("Enter CVE ID (e.g., CVE-2021-34527): ")
            get_cve_details(cve_id)
            technique_id = cve_mappings.get(cve_id)
        
        elif choice == "2":
            technique_id = input("Enter Technique ID (e.g., T1068): ")
            attack_data = get_attack_data()
            technique_name, technique_desc, technique_url, mitigations = get_technique_details(technique_id, attack_data)
        
        elif choice == "3":
            threat_actor = input("Enter Threat Actor Name: ")
            get_threat_actor_details(threat_actor)
        
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()