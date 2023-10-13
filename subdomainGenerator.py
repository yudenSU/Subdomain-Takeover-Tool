import subprocess
import platform
import json

class SubdomainFinder:
    def __init__(self, enumOutput):
        self.config_file_path = "./config.json"
        self.config_data = self.load_config()
        self.enumOutput = enumOutput

    def load_config(self):
        try:
            with open(self.config_file_path, "r") as config_file:
                config_data = json.load(config_file)
            return config_data
        except FileNotFoundError:
            raise FileNotFoundError("Config file not found")
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON format in config file")

    def get_amass_path(self):
        # Determine the operating system type
        os_type = platform.system().lower()
        # Retrieve the amass_path based on the operating system
        return self.config_data.get(os_type, {}).get("amass_path")

    def find_subdomains_amass(self, target_domain):
        print("Starting AMASS enumeration..")
        try:
            amass_path = self.get_amass_path()

            if not amass_path:
                return "Amass path not specified for this operating system"

            cmd = [amass_path, "enum", "-o", self.enumOutput, "-d", target_domain]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Split the output into lines and extract subdomains
            output_lines = result.stdout.strip().split('\n')
            subdomains = [re.sub(r'\([^)]*\)|-->', ',', line.strip()) for line in output_lines]
            print("AMASS enumeration finished")
            return subdomains
        except Exception as e:
            return str(e)
