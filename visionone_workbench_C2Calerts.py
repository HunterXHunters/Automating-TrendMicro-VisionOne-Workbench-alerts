import requests
import json
#import vt
import time
from datetime import datetime, timedelta
#from stix2.v21 import (Indicator, KillChainPhase, Malware, Relationship, Bundle)


# Virustotal API

vtapi_key = "YOUR_VIRUSTOTAL_API_KEY"
vturl = 'https://www.virustotal.com/vtapi/v2/url/report'

#VisionOne Workbench Alert

url_base = 'https://api.xdr.trendmicro.com' # VisionOne URL
url_path = '/v3.0/workbench/alerts' # Workbench Alert API 
oat_path = '/v3.0/oat/detections'   # Observed Attack Technique API
suspiciousObjects_path = '/v3.0/threatintel/suspiciousObjects' # Suspicious Object Management API
updatenotes_path = '/v3.0/workbench/alerts/{alertId}/notes' # Workbench Alert Investigation Notes API

#API Token
token = "YOUR_VISIONONE_API_KEY"


#######################################################################################################################################
# Date & Time Picker to fetch alerts from specific period
        
d = datetime.now() #gets Todays time
endDate= d.strftime("%Y-%m-%dT%H:%M:%SZ") #Keeping todays date as EndDate and Converting to ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) 
new_startDate = d - timedelta(days=10)    # Deduction -10 days to create Start date i.e. Datetime between "startDateTime" and "endDateTime" is 10 days to be used for retrieving alert data.
startDate = new_startDate.strftime("%Y-%m-%dT%H:%M:%SZ") # Converting StartDate to ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) 


#######################################################################################################################################

#######------ Workbench API to get all alerts ------#######

# - Workbench alert Params 
query_params = {'startDateTime': startDate,
    'endDateTime': endDate,
    'dateTimeTarget': '',
    'orderBy': 'createdDateTime desc'}
# - Workbench Header Request Query to filter with New workbench alerts with respect to Possible Spear Phishing Attack via Links
headers = {'Authorization': 'Bearer ' + token, 'TMV1-Filter': "model eq 'Possible Spear Phishing Attack via Link' and investigationStatus eq 'New'"}

# request sent to VisionOne to fetch all workbench alerts with status New
r = requests.get(url_base + url_path, params=query_params, headers=headers)

#print(r.status_code)
if 'application/json' in r.headers.get('Content-Type', '') and len(r.content):
      
    workbench_alert = json.dumps(r.json(), indent=4)
    data = json.loads(workbench_alert)

    
    #Extract workbench ID (wid) which is used later to update Investigation Notes with comments in workbench specific alert
    wid = data['items'][0]["id"]
  
    ######### Comparision with first record by exctrating model from JSON and checking if it is equal or no ########################## 
    if data['items'][0]['model'] == "Possible Spear Phishing Attack via Link":
        
        print("\n \nWe are analyzing 'Possible Spear Phishing Attack via Link' workbench alert")
        print("")
        
        #######------ Observed Attack Technique to get Highlighted URLs/IOCs ------#######
        
        #Observed Attack Technique Params and we are fetching recent detection (top:1) as we will be analyzing 1 alert at a time.
        oat_params = {'detectedStartDateTime': startDate,
                        'detectedEndDateTime': endDate,
                        'ingestedStartDateTime': startDate,
                        'ingestedEndDateTime': endDate,
                        'top': '1'}
       
        #print (data['items'][0]['matchedRules'][0]['matchedFilters'][0]['matchedEvents'][0]['uuid'])
        uuid = data['items'][0]['matchedRules'][0]['matchedFilters'][0]['matchedEvents'][0]['uuid']
        
        oat_headers = {'Authorization': 'Bearer ' + token, 'TMV1-Filter': "uuid eq '%s'"%uuid}
        
        ###### OAT Request 
        r = requests.get(url_base + oat_path, params=oat_params, headers=oat_headers)
        #print(r.status_code)
        
        
        if 'application/json' in r.headers.get('Content-Type', '') and len(r.content):
            #print(json.dumps(r.json(), indent=4))
            oat_event = json.dumps(r.json(), indent=4)
            oat_data= json.loads(oat_event)
            #print (oat_data)
            
            ######## Extracting IOC- Highlighted Requests Observed from OAT
            #print (oat_data['items'][0]['detail']['highlightedRequest'])
            highlightedRequest = oat_data['items'][0]['detail']['highlightedRequest']
            
            print("Summary:")
            print("\nPossible Spear Phishing Attack via Link \n A suspicious URL associated with phishing attacks was detected in an email message.")
            print("")
            print("Highlights- Spearphishing Link Addressed by RetroScans \n")
            print(highlightedRequest)
            print("")
            ############################ Intial Lookup to VirusTotal######################################
            print("++++++++++++++ Intial Analysis with Threat Intelligence Lookup +++++++++++++++ \n")
            print("Sending URLs to VirusTotal")
            
            ################ Storing IoCs in indicators to send URLs to VirusTotal #################
            indicators = highlightedRequest

            for site in indicators:
                vtparams = {'apikey': vtapi_key, 'resource': site} #VT params
                response = requests.get(vturl, params= vtparams) 
                response_json = json.loads(response.content) #VT JSON
                #print (response_json)
                ##### Comparision for VT Reputation.####
                if response_json['positives'] <= 0:
                    print (response_json['resource']+' is Not Malicious and needs no furthure actions')
                    
                elif response_json['positives'] < 3:
                    print (response_json['resource']+ " Maybe Malicious which requires manual investigation and if found abnormal, please add findings to Suspicious Object list")
                    
                elif response_json['positives'] > 3:
                    x = response_json['resource']
                    print ("\n URL: %s is submitted for analysis"%x)
                    
                    time.sleep(3)
                    print(" "+response_json['resource']+ " is found Malicious and next steps follows")
                    
                    #print (x)
                    
                    
                    #######------Suspicious Object Management API to block IOC in Threat Intelligence module ------#######
                    # Block URLs in Threat Intelligence                    
                    
                    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json;charset=utf-8'}
                    body = [{'url': site, 'description': 'VT Reputation is Bad','scanAction': 'block', 'riskLevel': 'Low', 'daysToExpiration': '90'}]
                    r = requests.post(url_base + suspiciousObjects_path, params=query_params, headers=headers, json=body)
                    #print(r.status_code)
                    if 'application/json' in r.headers.get('Content-Type', '') and len(r.content):
                    
                        #print(json.dumps(r.json(), indent=4))
                        print("++++++++++++++ Containment Stratergy +++++++++++++++ \n")
                        print("Blocking suspicious highlighted request in VisionOne Threat Intelligence Suspicious Object Management")
                        print(" Added URL %s to block list \n"%x)

                    else:
                        print(r.text)
                        
                     #######------ Workbench Notes Alert API to update comments in specific workbench alert ------#######    
               
                    updatenotes_path = updatenotes_path.format(**{'alertId': wid})
                    headers = {'Authorization': 'Bearer ' + token,
                                'Content-Type': 'application/json;charset=utf-8'}
                    body = {'content': 'URL: %s is having Bad Reputation'%x}
                    
                    r = requests.post(url_base + updatenotes_path, headers=headers, json=body)
                    
                    print ("Adding analysis notes to workbench alert and coordinate with L2 team for closure as it is workbench alert")
                    print (" Added notes to workbench alert \n ")
                    
                    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                    
                else:
                    print("URL Not found")
                time.sleep(15)
          
        else: 
            print(r.text)
    else:
        print("This incident is not related to 'Possible Spear Phishing Attack via Link' workbench alert")
            
else:
    print(r.text)
    

