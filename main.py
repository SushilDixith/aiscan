import nmap
import openai
import logging
import json
import importlib
import os
from prettytable import PrettyTable
from config_file_loader import load_config

# Load the configuration
config = load_config()

# Extract settings from configuration
api_key = config.get("openai_api_key")
if not api_key or api_key == "YOUR_DEFAULT_API_KEY":
    raise ValueError("OpenAI API key is missing or set to the default value. Please configure it correctly in the config file.")
openai.api_key = api_key

ai_engine = config.get("ai_engine", "text-davinci-003")
ai_max_tokens = config.get("ai_max_tokens", 100)
output_format = config.get("output_format", "table")
logging_level = config.get("logging_level", "ERROR")

# Configure logging
logging.basicConfig(level=getattr(logging, logging_level.upper(), logging.ERROR))

MODULE_DIR = "modules"

def load_scan_module(module_name):
    try:
        module_path = f"{MODULE_DIR}.{module_name}"
        return importlib.import_module(module_path)
    except ModuleNotFoundError:
        logging.error(f"Module '{module_name}' not found.")
        return None

def list_available_modules():
    print("Available Scan Modules:")
    for file in os.listdir(MODULE_DIR):
        if file.endswith(".py") and file != "__init__.py":
            print(f"- {file[:-3]}")

def list_nmap_script_categories():
    print("Available Nmap Script Categories:")
    categories = [
        "auth", "broadcast", "brute", "default", "discovery", 
        "dos", "exploit", "external", "fuzzer", "intrusive",
        "malware", "safe", "version", "vuln"
    ]
    for idx, category in enumerate(categories, start=1):
        print(f"{idx}. {category}")

def analyze_results_with_ai(scan_results):
    try:
        response = openai.Completion.create(
            engine=ai_engine,
            prompt=f"Analyze the following Nmap scan results and provide security recommendations:\n{scan_results}",
            max_tokens=ai_max_tokens
        )
        return response.choices[0].text.strip()
    except Exception as e:
        logging.error(f"Error analyzing results with AI: {e}")
        return "AI analysis failed. No recommendations available."

def format_as_table(scan_results):
    table = PrettyTable()
    table.field_names = ["Port", "State", "Service", "Version"]
    for protocol in scan_results.all_protocols():
        ports = scan_results[protocol].keys()
        for port in ports:
            service = scan_results[protocol][port].get("name", "Unknown")
            version = scan_results[protocol][port].get("version", "Unknown")
            state = scan_results[protocol][port].get("state", "Unknown")
            table.add_row([port, state, service, version])
    return table

def validate_module_selection(module_name):
    available_modules = [file[:-3] for file in os.listdir(MODULE_DIR) if file.endswith(".py") and file != "__init__.py"]
    if module_name not in available_modules:
        print(f"Invalid module '{module_name}'. Please select a valid module from the list below:")
        list_available_modules()
        return False
    return True

def main():
    print("Welcome to the Modular AI-Enhanced Scanning Tool!")
    list_available_modules()
    list_nmap_script_categories()
    
    while True:
        selected_module = input("\nEnter the scan module to use: ").strip()
        if validate_module_selection(selected_module):
            break
    
    selected_category = input("Enter the Nmap script category to use (or press Enter to skip): ").strip()

    module = load_scan_module(selected_module)
    if not module:
        print("Invalid module. Exiting.")
        return

    target_ip = input("Enter target IP: ").strip()
    if not target_ip:
        print("No target IP provided. Exiting.")
        return

    print(f"\nRunning '{selected_module}' module on target: {target_ip}")
    scan_args = ""
    if selected_category:
        scan_args = f"--script {selected_category}"
        print(f"Using Nmap script category: {selected_category}")
    
    try:
        scan_results = module.run_scan(target_ip, scan_args)
    except Exception as e:
        logging.error(f"Scan execution failed: {e}")
        print("An error occurred during the scan. Please check the target IP and try again.")
        return

    if scan_results:
        print("\nScan Results:")
        print(format_as_table(scan_results))
        
        print("\nAnalyzing results with AI...")
        ai_analysis = analyze_results_with_ai(str(scan_results))
        if "AI analysis failed" in ai_analysis:
            print("AI Recommendations: Default fallback: Review port services and versions for known vulnerabilities.")
        else:
            print("AI Recommendations:")
            print(ai_analysis)
    else:
        print("No scan results available.")

if __name__ == "__main__":
    main()
