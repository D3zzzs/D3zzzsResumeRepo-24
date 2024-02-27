#!/usr/bin/env python3

"""
Author: Derek Iszczyszyn
Email: dwiszczyszyn@madisoncollege.edu
Description: This script will be an apache web log analyzer. 
We will be using it to see if anyone is attempting to hack our website.
"""

import subprocess,argparse,requests,json

def IPAddressCount(apache_log_file_name):
    command = f"cat {apache_log_file_name} | cut -d ' ' -f1 | sort -n | uniq -c | sort -n | tail -n5"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
    output = process.stdout
    return output     # ask about using stdout to inject filename, and use text=true instead of using decode

def ParseLogEntry(log_entry):
    logLineList = log_entry.split(' ')
    http_code = logLineList[8]
    ip_addr = logLineList[0]
    return_code = int(http_code)
    return [ip_addr, return_code]

def IPLookup(IPAddress):
    # Build the URL using string formatting, assigning it to a variable 
    url = (f"https://virustotal.com/api/v3/ip_addresses/{IPAddress}")  
    credFile = open('/home/student/.credentials-vt', 'r')
    credentials = credFile.readlines()
    api_key = credentials[0].split('=')[1].strip()
    headerVariable = {
        'x-apikey': api_key
    }
    #(f"http://ipinfo.io/{IPAddress}/json")
    response = requests.get(url, headers=headerVariable)
    print(url)
    return response.text


def main():
    parser = argparse.ArgumentParser(description="Apache Web Log Analyzer")
    parser.add_argument('-f', '--filename', required=True, type=str, help="Enter an Apache File Name to process")

    args = parser.parse_args()
    apache_log_file_name = args.filename
    
    myScriptDesc = """This script is an apache log analyzer"""
    print(myScriptDesc)

    ip_addr_count = IPAddressCount(apache_log_file_name)

    # Parse the response from IPAddressCount
   
    ip_addr_lines = ip_addr_count.split('\n')
    most_requested_ip = ip_addr_lines[-2].split()[-1]
    print(most_requested_ip)
    ip_lookup_result = IPLookup(most_requested_ip)
    #print(ip_lookup_result)
    ip_info = json.loads(ip_lookup_result)
    #print(json.dumps(ip_info, indent=4))
    bitdefender_category = ip_info['data']['attributes']['last_analysis_results'].get('BitDefender', {}).get('category')
    print(f"BitDefender category: {bitdefender_category}")
    #print(f"... IP City: {ip_info['city']}")
    #print(f"... IP ORG: {ip_info['org']}")
   #myHTML = bs4.BeautifulSoup(ip_lookup_result, features="html.parser")
   #print(myHTML.find_all("dd", class_="col-8 text-monospace")[1].text)

    with open ("apache_analysis.txt","w") as output_file: # Writes IP addresses with <5 hits to output_file
        output_file.write(ip_addr_count)


if __name__ == "__main__":
    main()
            # with open("m5-access.log", "r") as myLogList:
            #     myLog = myLogList.read()
            #     logList = myLog.split('\n')
            
            # apache_log_summary = {}

            # with open("apache_analysis.txt","w") as output_file: 
            #     for logLine in logList: # for loop
            #         ip_addr, return_code = ParseLogEntry(logLine)
                
            #         if ip_addr in apache_log_summary: #loops through dictionary looking for IP
            #             apache_log_summary[ip_addr] += 1 # adds one to count if ip already exists
            #         else:
            #             apache_log_summary[ip_addr] = 1 # if ip is not found in dictionary, add it to it and assign count of 1
            #         if return_code >= 400:
            #             summary = (f'{ip_addr} - {return_code}')
            #             print(summary)
            #     for ip, count in apache_log_summary.items(): 

            #        ^^^^ OLD CODE BEFORE SUBPROCESS MODULE ^^^^ PUT IT BETWEEN LAST ELSE STATEMENT AND THIRD IF STATEMENT