import re
import pandas as pd

class SubdomainOutputParser:
    def __init__(self,):
        self.fqdn_list = []
        self.record_type_list = []
        self.record_result_list = []
        self.df = None

    def parse_file(self, file_path):
        with open(file_path, "r") as file:
            for line in file:
                if "(FQDN)" in line:
                    components = line.strip().split(" --> ")
                    if len(components) == 3:
                        fqdn, record_type, record_result  = components
                        
                        fqdn = fqdn.replace("(FQDN)", "").strip()
                        record_result = re.sub(r'\([^)]*\)', '', record_result).strip()
                        
                        self.fqdn_list.append(fqdn)
                        self.record_type_list.append(record_type)
                        self.record_result_list.append(record_result)

    def create_dataframe(self):
        data = {
            "FQDN": self.fqdn_list,
            "record_type": self.record_type_list,
            "record_result": self.record_result_list
        }
        self.df = pd.DataFrame(data)

    def display_dataframe(self):
        if self.df is not None:
            print(self.df)
        else:
            print("DataFrame has not been created. Call create_dataframe() after parsing.")

    def retrieve_dataframe(self):
        return self.df
