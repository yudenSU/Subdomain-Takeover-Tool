import argparse
from subdomainGenerator import SubdomainFinder
from controller import Contoller

def CLI():


    # List of valid output types
    valid_output_types = ['csv', 'excel', 'html', 'json', 'pickle', 'parquet', 'feather', 'msgpack', 'stata', 'png', 'svg', 'pdf']

    # Create the argument parser
    parser = argparse.ArgumentParser()

    # Define the arguments
    parser.add_argument('-d', '--domain', help='Input the target domain, e.g., facebook.com')
    parser.add_argument('-ss', '--skipScan', help='If set to "false", we will not scan for vulnerabilities', action='store_false')
    parser.add_argument('-se', '--skipEnumerate', help='If set to "false", we will only scan a provided amass output txt file', action='store_false')
    parser.add_argument('-rn', '--reportName', help='Set the name of the output file do not add an extension', required=False, default='report')
    parser.add_argument('-ot', '--outputType', help=f'Set the output type ({", ".join(valid_output_types)})', required=False, default='csv')
    # Parse the arguments
    args = parser.parse_args()


    # Validate and set domain
    domain = args.domain

    # Parse the command-line arguments
    args = parser.parse_args()

    # Validate and set domain
    domain = args.domain

    enumerate = args.skipEnumerate
    scan = args.skipScan

    # Set output as a string
    output = args.reportName

    # Validate and set outputType as one of the valid output types
    outputType = args.outputType.lower()

    if outputType not in valid_output_types:
        print("Invalid value for 'outputType'. Please choose from:", ', '.join(valid_output_types))
        outputType = None

    args = parser.parse_args()

    if not domain:
        print("Please provide a target domain using the -d or --domain option.")
        return
    
    
    controller = Contoller(vulnerabilityReportOutput = output, reportFileType= outputType)

    if (enumerate):
        controller.performSubdomainEnumeration(args.domain)
    if (scan):
        controller.retriveSubdomainDataFrame()
        controller.performVulnerabilityCheck()
    
    controller.makeReport(output, outputType)


if __name__ == "__main__":
        CLI()