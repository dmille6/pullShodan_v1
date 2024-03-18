import shodan
import time
from datetime import datetime, timedelta
from os import path
import argparse
import yaml
from elasticsearch import Elasticsearch
import os
from tqdm import tqdm
import json

def get_data_key_fields(logItem):
    fields = list(logItem.keys())
    return fields

def count_vulns(vulns):
    return (len(vulns.keys()))

def list_vulns(vulns):
    return list(vulns.keys())

def parse_shodan_item(item,config):
    shodanItem = {}
    tags = []

    for field in get_data_key_fields(item):
        if field in config['keyfields']:
            if field == 'vulns':  # because of the way shodan stores this information it has to be normalized/modified
                shodanItem["vulns_count"] = count_vulns(item["vulns"])
                item["vulns"] = list_vulns(item["vulns"])
            if field == 'mac':
                item["mac"] = str(item["mac"])
                item["mac"] = item["mac"].replace('{', '')
                item["mac"] = item["mac"].replace('}', '')
            if field == 'location':  # put the geo ip info in a form ES can use
                geo = {}
                geo['lon'] = item['location']['longitude']
                geo['lat'] = item['location']['latitude']
                item['location']['geo'] = geo.copy()
                geo = {}
            shodanItem[field] = item[field]
        else:
            tags.append(field)

    shodanItem['tags'] = tags.copy()
    shodanItem['shodan_link'] = "https://shodan.io/host/" + shodanItem['ip_str']
    return shodanItem.copy()

# *********************************************************************************
if __name__ == "__main__":
    # start timer
    script_start = time.time()
    currentTime = datetime.now()

    # ------------- Reads Config File ---------------
    YAMLFILE = "./config.yaml"  # System Configuration and Variables

    if path.exists(YAMLFILE):
        # -- Loads Configuration File for LookOut --> python dictionary
        with open(YAMLFILE, "r") as file:
            config = yaml.load(file, Loader=yaml.FullLoader)
    else:
        print(
            "ERROR: No config file, please refer to lookout.yml.example in root folder of script"
        )
        exit()

    print(f"[+]: Current Configuration: {config}")

    # ------- Creates Data Folder if it doesnt exist -----------
    path = config['data_folder']
    # Check whether the specified path exists or not
    isExist = os.path.exists(path)
    if not isExist:
        # Create a new directory because it does not exist
        os.makedirs(path)
        print("The new directory is created!")
    # ----------------------------------------------------------

#Set your API key
SHODAN_API_KEY = config['shodan_api_key']

# Initialize the Shodan API client
api = shodan.Shodan(SHODAN_API_KEY)

# Calculate the date for yesterday
yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

try:
    d = datetime.today().strftime("%Y-%m-%d-%s")
    count=0

    # formatting query with proper date
    query = config['shodanQuery']
    query = query.replace("<<time_differential>>", yesterday)

    fileString=query.replace('"','-')
    fileString=fileString.replace(":","")
    fileString = fileString.replace(" ", "")
    fileString = fileString.replace("202", "-202")

    filename = config['data_folder'] + "/" + "shodan-query-" + fileString + "-"+ d + ".json"
    print(f'Filename: {filename}')
    file_writer = open(filename, "w")

    # Define the number of results per page
    results_per_page = 1000

    # Define the number of pages you want to fetch
    num_pages = 5  # Change this to the number of pages you want

    # Perform the search and paginate through the results
    for page in range(1, num_pages + 1):
        try:
            # Perform the search
            results = api.search(query, page=page, facets={'country', 'state'})

            # Print the results
            for result in results['matches']:
                count+=1
                ## do work here ##
                shodan_parsed_item=parse_shodan_item(result, config)
                file_writer.write((str(shodan_parsed_item)+"\n"))
                ##################
                print(f'   [{count}] :    {result['ip_str']} : {shodan_parsed_item}')

        except shodan.APIError as e:
            print('Error: %s' % e)

except Exception as e:
    print('Error: {}'.format(e))