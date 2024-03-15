#Load envirement from .env faile 
import os
from dotenv import load_dotenv
load_dotenv()

#PART OFF TCP SERVER FOR RECIVE LOG FROM GREENBONE SCANER
#Fix shit of python
import sys
sys.path.insert(0,'/usr/local/lib/python3.10/dist-packages')

# import xml.etree.ElementTree as ET
import re

import socket
from _thread import *

def client_handler(conn):
    try:
       data = re.sub(r'(.*id=\")|(\">.*)', '', conn.recv(int(os.getenv('SIZE'))).decode(os.getenv('FORMAT'))) 
    except: print('Error when receiving report from Greenbone')
    # xml_data = ''
    # data = conn.recv(1024).decode(os.getenv('FORMAT'))
    # while data:
    #     if not data: break
    #     else:
    #         xml_data += data
    #         data = conn.recv(1024).decode(os.getenv('FORMAT'))
    conn.close()
    #pretty_print(xml_data)
    # print(re.sub(r'(.*id=\")|(\">.*)', '', data))
    #print(ET.fromstring(data).attrib.get('id'))
    # data = re.sub(r'(\">.*)$', '', data) + '</report>'
    
    # print(data)
    # print(ET.fromstring(data).attrib.get('id'))
    try:
        make_report(data)
    except: print('Cant get report id')
      

def accept_connections(ServerSocket):
    Client, address = ServerSocket.accept()
    start_new_thread(client_handler, (Client, ))

def start_server(host = socket.gethostbyname(socket.gethostname()), port = int(os.getenv('PORT'))):
    ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ServerSocket.bind((host, port))
    except socket.error as e:
        print(str(e)) 
    ServerSocket.listen()
    while True:
        accept_connections(ServerSocket)


#PART WITH MAKING REPORT
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
from base64 import b64decode

def return_hostname(xml_data):
    for item in xml_data.xpath('detail'):
            if(item.xpath('name/text()')[0] == "hostname"):
                return item.xpath('value/text()')[0]

def culculate_domains(xml_data):
    # hosts = ["omegalol.xyz", "lol.cz2d.com", "hello.cz2d.com", "meravera-1.core64.cz", "omegalol.xyz", "cz2d.com", "dfdf.sds.dfd", "dsfddf.com", "omegalol.xyz", "lol.cz2d.com", "cz2d.com", "omegalol.xyz", "lol.cz2d.com"]
    addresses = []
    domains = {}
    # hostnames += hosts
    # pretty_print(xml_data)
    for item in xml_data:

        hostFqdn = return_hostname(item)
        ip = item.xpath('ip/text()')[0] 

                
        # print(re.sub(r'\.\w+$', '', item.text) + ".unassigned")
        # # print(hostFqdn + "\n\n")
        if not hostFqdn: hostFqdn = "." + re.sub(r"\.\w+$", '', ip) + ".unassigned"
        # print(hostFqdn)
        # if hostFqdn in addresses: continue  
        # else:           
        addresses.append(hostFqdn) 
        domain = re.sub(r'^.*?\.', '', hostFqdn)
        if domain in domains: 
            domains[domain] = domains.get(domain) + 1
        else:
            domains[domain] = 1         
    return domains

def make_report(uuid):

    connection = UnixSocketConnection()
    transform = EtreeTransform()

    with Gmp(connection, transform = transform) as gmp:
        try:
            gmp.authenticate(os.getenv('GVM_USERNAME'), os.getenv('GVM_PASSWORD'))
        except: print('GVM authenticate failed!')
        
        #make pdf report
        try:
            pdf_report_format_id = "c402cc3e-b531-11e1-9163-406186ea4fc5"
            pdf_report = gmp.get_report(
            report_id = uuid, report_format_id = pdf_report_format_id, filter_string = os.getenv('FILTER') + ' first=1 levels=hml sort-reverse=qod ' + os.getenv('ROWS')
        )
        except: print('Get PDF report (' + uuid + ') error')
        try:
            pdf_report_element = pdf_report.find("report")
            pdf_content = pdf_report_element.find("report_format").tail
            binary_base64_encoded_pdf = pdf_content.encode("ascii")
            binary_pdf = b64decode(binary_base64_encoded_pdf)         
        except: print('Encode PDF report (' + uuid + ') error')

        valid_report_name = "".join(x for x in pdf_report.xpath('report/task/name/text()')[0] if x.isalnum())

        try:
            with open(os.getenv('REPORT_PATH') + valid_report_name + '.pdf', 'wb') as f: 
                f.write(binary_pdf)
        except: print('Error when PDF report (' + uuid + ') save to ' + pdf_report.xpath('report/task/name/text()')[0] + '.pdf')

        #make short table report
        MASSAGE = 'Report from task: **[' + pdf_report.xpath('report/task/name/text()')[0] + '](https://greenbone-1.cz2d.cloudevelops.lan:9392/report/' +  uuid + ')**\n'
        MASSAGE += "\n\n|  Hosts found |  All Result  | High |  Medium  | Low|\n"
        MASSAGE += "| -------  | -------  | ------- | ------- | ------- |"

        xml_report_format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"
        try:
            # xml_reports = gmp.get_reports(
            #     filter_string = "task_id=" + pdf_report.xpath("report/task")[0].get("id"), details = False, note_details = False
            #     #filter_string = 'task_id=' + pdf_report.xpath("report/task")[0].get("id") + ' ' + os.getenv('FILTER'), details = False, note_details = False
            # ).xpath('report')
            xml_report = gmp.get_report(
            report_id = uuid, report_format_id = xml_report_format_id, ignore_pagination  = True
            ).xpath('report')[0]
        except: print('Error when receiving info about task ('+ pdf_report.xpath("report/task")[0].get("id") +')')
        try:
            # for report in xml_reports:              
            #     if(report.get("id") == uuid):
            #         #pretty_print(report)
            #         MASSAGE += "\n| " + report.xpath('report/hosts/count/text()')[0] + " | " + report.xpath('report/result_count/full/text()')[0] + " | " + report.xpath('report/result_count/hole/filtered/text()')[0] + " | " + report.xpath('report/result_count/warning/filtered/text()')[0] + " | " + report.xpath('report/result_count/info/filtered/text()')[0] + " | "
            #         break;
            MASSAGE += "\n| " + xml_report.xpath('report/hosts/count/text()')[0] + " | " + xml_report.xpath('report/result_count/full/text()')[0] + " | " + xml_report.xpath('report/result_count/hole/filtered/text()')[0] + " | " + xml_report.xpath('report/result_count/warning/filtered/text()')[0] + " | " + xml_report.xpath('report/result_count/info/filtered/text()')[0] + " | "
            MASSAGE += "\n\n|  Domain name |  Number of hosts|\n"
            MASSAGE += "| ---------  | ---------  |"

            for domain, amount in culculate_domains(xml_report.xpath('report/host')).items():
                MASSAGE += "\n| " + domain + " | " + str(amount) + " | "
        except: print('Zerro info incide task ('+ pdf_report.xpath("report/task")[0].get("id") +')')
        #print(MASSAGE)
        send_report((os.getenv('REPORT_PATH') + valid_report_name + '.pdf', MASSAGE))


#PART WITH MATTERMOST
import json
import requests
import subprocess

def send_report( payload, SERVER_URL = os.getenv('SERVER_URL'), CHANNEL_ID = os.getenv('CHANNEL_ID')):
    try:
        s = requests.Session()
        s.headers.update({"Authorization": "Bearer " + os.getenv('MM_SELF_TOKEN')})
    except: print('Mattermost API authontication failed!')
    try:
        form_data = {
            "channel_id": ('', CHANNEL_ID),
            "client_ids": ('', "id_for_the_file"),
            "files": (os.path.basename(payload[0]), open(payload[0], 'rb')),
        }
        r = s.post(SERVER_URL + '/api/v4/files', files=form_data)

        FILE_ID = r.json()["file_infos"][0]["id"]

        p = s.post(SERVER_URL + '/api/v4/posts', data=json.dumps({
            "channel_id": CHANNEL_ID,
            "message": payload[1],
            "file_ids": [ FILE_ID ]
        }))
    except: print('Error send report to Mattermost')
    try:
        subprocess.run(['rm ' + payload[0]], shell=True)
    except: print('File '+ payload[0] +' dosnt exist')

def main():
    start_server()
    #make_report('91a4bc81-7163-4bc1-ab41-decff7832258')

if __name__ == "__main__":
    main()