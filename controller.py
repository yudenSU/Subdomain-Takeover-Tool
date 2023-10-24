import time
from EnumerationOutputParser import SubdomainOutputParser
from subdomainGenerator import SubdomainFinder
from subdomainVulnerabilityScanner import SubdomainVulnerabilityScanner
import pandas as pd

class Contoller:
    def __init__(self, enumerationOutput = "./output/EnumerationOutput.txt", vulnerabilityReportOutput = "Report", reportFileType = "csv"):
        #parse params
        self.enumerationOutput = enumerationOutput
        self.vulnerabilityReportOutput =  vulnerabilityReportOutput
        #create classes
        self.subdomainVulnerabilityScanner = SubdomainVulnerabilityScanner()
        self.subdomain_output_parser = SubdomainOutputParser()
        self.subdomain_finder = SubdomainFinder( self.enumerationOutput)
        #other variables
        self.subdomainDataFrame =  pd.DataFrame(columns=["FQDN", "record_type", "record_result"])

    
    def performSubdomainEnumeration(self, target_domain):
        start_time = time.time()

        self.subdomain_finder.find_subdomains_amass(target_domain)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Enumeration took {elapsed_time:.2f} seconds")

    def retriveSubdomainDataFrame(self):
        self.subdomain_output_parser.parse_file(self.enumerationOutput)
        self.subdomain_output_parser.create_dataframe()
        self.subdomainDataFrame = self.subdomain_output_parser.retrieve_dataframe()

    def performVulnerabilityCheck(self, checkCNAME = True, checkNS = True):
        start_time = time.time()

        if checkCNAME:
            self.subdomainVulnerabilityScanner.nsVulnerabilityCheck(self.subdomainDataFrame)
        if checkNS:
            self.subdomainVulnerabilityScanner.cnameVulnerabilityCheck(self.subdomainDataFrame)

        print(self.subdomainVulnerabilityScanner.retrieveResults())
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Vulnerability check took {elapsed_time:.2f} seconds")


    def makeReport(self, vulnerabilityReportOutput ,reportType):
        self.subdomainVulnerabilityScanner.createReport(vulnerabilityReportOutput, reportType)