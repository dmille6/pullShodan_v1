# parseShodan_v1.py
# https://github.com/dmille6/pullShodan_v1
# darrellrhodesmiller@gmail.com
#
# ######################################################
# Parse Shodan v1:
# this is a very ugly and early script to parse shodan exports created by the shodan cli
# and dump useful portions of that file into elasticsearch
#
# Notes/Thoughts:
# the shodan json does not go directly into elasticsearch very well because of its structure.
# elasticsearch has a limit of fieldnames, by default that limit is 1000 (it can be increased)
# but shodan creates new field names for each application or vulnerability.. which creates
# a field explosion.. and just makes it nearly impossible to import 1:1 from shodan json -> es.
# if anyone knows a good way .. or finds a good way.. PLEASE let me know.
#
# i created a list of key important fields that i import directly. the rest of the stuff is left
# out to prevent field explosions.. i have a field that has a direct link to the shodan webpage
# for the entry to see the rest of the information.
#
# long term, probably something like mongoDB would be a better choice for storing this information
# and can handle the field problems i am experiencing with elasticsearch.. but that would require
# me to learn visualization and a new database structure.. and this seems good enough for now.
#
# Done:
# -- parsing of a folder of shodan exported json files
# -- dump *most* of the important data into elasticsearch
# To Do:
# -- improve this process (more efficient)
# -- clean up code to make it more readable
# -- create some sort of vulnerabilty scoring algorith to rate entries by how terrible they are
# -- create templates and visualizations in kibana
# -- save those templates and visualizations in files that can be included in this github, and
#    a mechanism to import them automatically
# -- create some clean simple reports that can be given to outside agencies
# -- use the python shodan API instead of the shodan CLI to pull the data, just a cleaner approach
# Wish i knew how to do:
# -- import the entire shodan data entry into some type of data store for long term analysis,
#    and to find trends over time
#

import os
import json
from tqdm import tqdm
from elasticsearch import Elasticsearch
from pycvesearch import CVESearch
from datetime import datetime
from pydantic import BaseModel
from pprint import pprint

class parseShodan:
    # fields i've deemed as important, cant import everything because of issues mentioned above
    keyfields =  ['_shodan','asn','bgp','cpe','cpe23','data','device','devicetype','dns','domains','hash','hostnames','html','http','info','ip','ip_str','ipv6','isp','location','mac','org','os','opts','port','product','tags','timestamp','title','transport','version','vulns']

    def __init__(self):
        print (f'[INFO] Initializing Shodan Object')
        self.es_host = 'http://10.0.0.25'
        self.es_port = 9200
        self.es_username = 'elastic' # default change this
        self.es_password = 'elastic' # default change this
        self.index_name = 'shodan_scan'

        # creates a list of files in the ./data folder to process
        # todo: change from hard coded folder to one given by user
        files_to_process=self.get_json_files_in_folder('./data')

        # parse each item in the filelist
        for item in files_to_process:
            self.parse_file(item, './data')

    def get_json_files_in_folder(self, folder_path):
        print (f'[INFO] Reading files.. ')
        files = os.listdir(folder_path)
        # Filter out only JSON files
        json_files = [file for file in files if file.endswith('.json')]
        return json_files

    def parse_file(self, json_file, folder_path):
        shodanItem={}
        tags=[]

        file_path = os.path.join(folder_path, json_file)
        fileReader = open(file_path, "r")

        fileData = fileReader.readlines()

        for item in tqdm(fileData):
            jsonData = json.loads(item)
            for field in self.get_data_key_fields(jsonData):
                if field in self.keyfields:
                    if field == 'vulns': #because of the way shodan stores this information it has to be normalized/modified
                        shodanItem["vulns_count"]=self.count_vulns(jsonData["vulns"])
                        jsonData["vulns"] = self.list_vulns(jsonData["vulns"])
                        #shodanItem["vulns"].pop()
                        self.query_cve(jsonData["vulns"])
                        #jsonData['vulns']=self.refactor_vulns(jsonData["vulns"])
                    if field == 'mac':
                        jsonData["mac"]=str(jsonData["mac"])
                        jsonData["mac"]=jsonData["mac"].replace('{','')
                        jsonData["mac"] = jsonData["mac"].replace('}', '')
                    if field == 'location': # put the geo ip info in a form ES can use
                        geo={}
                        geo['lon']=jsonData['location']['longitude']
                        geo['lat']=jsonData['location']['latitude']
                        jsonData['location']['geo']=geo.copy()
                        geo={}
                    shodanItem[field] = jsonData[field]
                else:
                    tags.append(field)

            shodanItem['tags']=tags.copy()
            shodanItem['shodan_link'] = "https://shodan.io/host/" + shodanItem['ip_str']
            #self.submit_to_es(shodanItem)
            tags=[]
            shodanItem={}


    def clean_vulnerable_configuration(self, vuln_config):
        v_list=[]

        for v in vuln_config:
            v_text=v['title']
            v_text = v_text.replace(':*', '')
            v_list.append(v_text)
        return v_list.copy()

    def clean_vulnerable_product(self, product_config):
        v_list=[]
        for v in product_config:
            v_text=v
            v_text=v_text.replace(':*','')
            v_list.append(v_text)
        return v_list.copy()

    # not useful at a moment will probably be removed, a failed attempt at enrichment,
    # just adds a lot of data that isnt really needed
    def query_cve(self, vuln_list):
        #todo: make cache to save query limit
        #todo: find max cvss
        #todo: find avg cvss
        #todo: find mode cvss (most common score)
        #todo: find total cvss

        cve = CVESearch('https://cve.circl.lu')

        for cve_Search in vuln_list:
            cve_dict={}
            cve_item=cve.id(cve_Search)
            if cve_item.get('vulnerable_configuration'):
                vuln_config_list=self.clean_vulnerable_configuration(cve_item.get('vulnerable_configuration'))

            if cve_item.get('vulnerable_product'):
                vuln_product_list=self.clean_vulnerable_product(cve_item.get('vulnerable_product'))

            cve_dict['cve_id'] = cve_item['id']
            cve_dict['Summary'] = cve_item['summary']
            cve_dict['Publish_Date'] = cve_item['Published']
            cve_dict['Last_Modified'] = cve_item['Modified']
            cve_dict['CVSS_Score'] = cve_item['cvss']
            cve_dict['References']= cve_item['references']
            cve_dict['Vulnerability_Configs'] = vuln_config_list
            cve_dict['Vulnerability_Products'] = vuln_product_list

            print (cve_dict)

    def get_data_key_fields(self, jsonData):
        fields=list(jsonData.keys())
        return fields

    def refactor_vulns(self,vulns):
        vulnsList=[]

        for vuln in vulns:
            vulns[vuln]['cve_id']=vuln
            vulnsList.append(vulns[vuln])

        return vulnsList.copy()

    def count_vulns(self, vulns):
        return (len(vulns.keys()))

    def list_vulns(self, vulns):
        return list(vulns.keys())

    def submit_to_es(self,jsonData):
        # Connect to Elasticsearch cluster with authentication
        es = Elasticsearch(
            [f"{self.es_host}:{self.es_port}"],
            http_auth=(self.es_username, self.es_password)
        )
        es.
        data = jsonData.copy()

        # Submit data to Elasticsearch
        es.index(index=self.index_name, body=data)

        # Refresh index
        es.indices.refresh(index=self.index_name)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    #read_json_files_in_folder("./data")

    shondan_parser_obj=parseShodan()