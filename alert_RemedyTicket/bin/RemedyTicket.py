#===============================================================================
#
#         	          FILE:	RemedyTicket.py
#
#         	         USAGE: python RemedyTicket.py
#
#	           DESCRIPTION:	Custom Alert Action for Raise_Remedy_Ticket PROD    
#
#          	       OPTIONS: ---
#
#    	      REQUIREMENTS: ---
#
#                     BUGS: ---
#
#              	     NOTES: ---
#
#     	      	    AUTHOR: Mohamed Ayman Mohamed Ibrahim 
#
#   		       VERSION: 1.0
#
#===============================================================================

#-----------------------------------------------------------------------#
#-----------------------Importing Python Modules------------------------#
#-----------------------------------------------------------------------#
import csv
import gzip
import datetime
import sys
import json
import os
import httplib
import base64
import string
import random
import requests
import socket
import requests.packages.urllib3
from prettytable import PrettyTable
import smtplib
import re
#-----------------------------------------------------------------------#



#
#  +--------------------------------------------------------------------------------------+
#  | Function: format_time()					                                                  |
#  |					       		                                                      |
#  | Foramtting Date & Time as required              |
#  +--------------------------------------------------------------------------------------+
#

def format_time():
    t = datetime.datetime.now()
    s = t.strftime('%m-%d-%Y %H:%M:%S.%f')
    return s[:-3]

#
#  +--------------------------------------------------------------------------------------+
#  | Function: LOG(MSG)					                                                  |
#  |					       		                                                      |
#  | Print Messages as log to ./CustomAlertActionLOG prefixed by Date |
#  | >> Arguments: MSG      			                                                  |
#  +--------------------------------------------------------------------------------------+
#

def LOG(message):
    with open(os.path.join(os.environ['SPLUNK_HOME'], 'var/log/splunk', 'modalert_fileoutput_Raise_Remedy_Ticket_prod.log'), 'a') as f:
        f.write(format_time() + " -0000 " + message + "\n")

#
#  +--------------------------------------------------------------------------------------+
#  | Function: Capture_Retrieved_Results()					                              |
#  |					       		                                                      |
#  | Function Responsible to capture STDIN sent by splunk when alert is fired on splunk   |
#  | >> Returns: results, search      			                                          |
#  +--------------------------------------------------------------------------------------+
#

def Capture_Retrieved_Results():
   LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Started")
   try:
      if __name__ == "__main__":
         if len(sys.argv) > 1 and sys.argv[1] == "--execute":
            LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Capturing Alert Attributes ")
#            payload = json.loads(sys.stdin.read())
#      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting Results File Path")
#      results = payload.get('results_file')
#      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting Search Name")
#      search = payload.get('search_name')
#      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Returning Results Path & Search Name")
#      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Finished")
#      return results,search
            settings = json.loads(sys.stdin.read())

      TicketSummary = settings['configuration'].get('TicketSummary')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting TicketSummary: "+str(TicketSummary)+"\n")

      TicketNotes = settings['configuration'].get('TicketNotes')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting TicketNotes: "+str(TicketNotes)+"\n")

      WorkInfoSummary = settings['configuration'].get('WorkInfoSummary')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting WorkInfoSummary: "+str(WorkInfoSummary)+"\n")

      WorkInfoNotes = settings['configuration'].get('WorkInfoNotes')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting WorkInfoNotes: "+str(WorkInfoNotes)+"\n")

      Priority = settings['configuration'].get('Priority')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting Priority: "+str(Priority)+"\n")

      TroubleSubject = settings['configuration'].get('TroubleSubject')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting TroubleSubject: "+str(TroubleSubject)+"\n")            

      AssigneeArea = settings['configuration'].get('AssigneeArea')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting AssigneeArea: "+str(AssigneeArea)+"\n")

      NotesAttachResults = settings['configuration'].get('NotesAttachResults')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting NotesAttachResults: "+str(NotesAttachResults)+"\n")

      SendMailNotification = settings['configuration'].get('SendMailNotification')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting SendMailNotification: "+str(SendMailNotification)+"\n")

      EmailAddress = settings['configuration'].get('EmailAddress')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting EmailAddress: "+str(EmailAddress)+"\n")
      WorkInfoAttachResults=settings['configuration'].get('WorkInfoAttachResults')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting WorkInfoAttachResults: "+str(WorkInfoAttachResults)+"\n")

      sid=settings.get('sid'),
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting sid: "+str(sid[0])+"\n")

      search_name=settings.get('search_name'),
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting search_name: "+str(search_name[0])+"\n")

      app=settings.get('app'),
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting app: "+str(app[0])+"\n")

      owner=settings.get('owner'),
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting owner: "+str(owner[0])+"\n")

      results_link=settings.get('results_link'),
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting results_link: "+str(results_link[0])+"\n")

      result=settings.get('result'),
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting result: "+str(result)+"\n")
  
      results_file=settings.get('results_file')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting results_file: "+str(results_file)+"\n")

      user_agent = settings['configuration'].get('user_agent', 'Splunk')
      LOG("INFO  sendmodalert - Capture_Retrieved_Results() -- Getting user_agent: "+str(user_agent)+"\n")


      return TicketSummary,TicketNotes, WorkInfoSummary, WorkInfoNotes, Priority, TroubleSubject, AssigneeArea, NotesAttachResults, SendMailNotification, EmailAddress, sid, search_name, app, owner, results_link, result, results_file, user_agent,WorkInfoAttachResults
   except:
      LOG("ERRO  sendmodalert - Capture_Retrieved_Results() Error")
      fh.close()
      exit()

#
#  +--------------------------------------------------------------------------------------+
#  | Function: Handling_Retrieved_Results()					                              |
#  |					       		                                                      |
#  | Extracting desired data from results.csv.gz file resulting from Alert fired          |
#  | >> Arguments: results      			                                              |
#  | >> Returns:   line      			                                                  |
#  +--------------------------------------------------------------------------------------+
#

def Handling_Retrieved_Results(results):
   LOG("INFO  sendmodalert - Handling_Retrieved_Results() -- Started")
   try:      
      LOG("INFO  sendmodalert - Handling_Retrieved_Results() -- Opening ResultsFile.CSV.GZIP")
      f = gzip.open(results, mode="rt")
      LOG("INFO  sendmodalert - Handling_Retrieved_Results() -- Opening ResultsFile.CSV")
      csvobj = csv.reader(f,delimiter = ',')
      LOG("INFO  sendmodalert - Handling_Retrieved_Results() -- Parsing Results into a List")
      Content=[]
      for line in csvobj:
          Content.append(line)
      
      LOG("INFO  sendmodalert - Handling_Retrieved_Results() -- Returning Results as List")
      LOG("INFO  sendmodalert - Handling_Retrieved_Results() -- Finished")
      return Content
   except:
      LOG("ERROR  sendmodalert - Handling_Retrieved_Results() Error")
      fh.close()
      exit()

#
#  +--------------------------------------------------------------------------------------+
#  | Function: Formating_Results()					                                      |
#  |					       		                                                      |
#  | Parsing desired data into XML Contexting to form XML String to be sent to OMI        |
#  | >> Arguments: DataAsList          			                                          |
#  | >> Returns:   XML_Context        			                                          |
#  +--------------------------------------------------------------------------------------+
#

def Formating_Results(TicketSummary, TicketNotes, WorkInfoSummary, WorkInfoNotes, Priority, TroubleSubject, AssigneeArea, search_name,NotesAttachResults, matrix,results_file,WorkInfoAttachResults,Type,INC):
   LOG("INFO  sendmodalert - Formating_Results() -- Started") 
   try:
      LOG("INFO  sendmodalert - Formating_Results() -- Generating XML Context") 
      DataContent="Results not attached"
      LOG("DEBUG  sendmodalert - Main() ----NotesAttachResults: "+NotesAttachResults)
      if Type == "Creation" :
         LOG("DEBUG  sendmodalert - Main() ---- IN if for "+Type)
         XML_Context="""{
            "TransactionContent" : "Ticket Creation",
            "CreateUpdateFlag" : "CREATE",
            "OriginatingSystem" : "Splunk",
            "IncidentNumber" : \"""" + str(search_name[0]) + """\",
            "Notes" : \"""" + str(TicketNotes) +"""\",
            "Summary" : \"""" + str(TicketSummary) + """\",
            "WorkInfoSummary" : \"""" + str(WorkInfoSummary) + """\",
            "WorkInfoNotes" : \"""" + str(WorkInfoNotes) + """\",
            "ReportedSource" : "Monitoring Event",
            "IncidentType" : "Incident",
            "Priority" : \"""" + str(Priority) + """\",
            "TroubleSubject" : \"""" + str(TroubleSubject) + """\",
            "AssigneeArea" : \"""" + str(AssigneeArea) + """\"
          }"""
      else:
         LOG("DEBUG  sendmodalert - Main() ---- IN if for "+Type)

         data = gzip.open(results_file, "r").read()
         encoded = base64.b64encode(data)

         LOG("Encoded: "+str(encoded))

         XML_Context="""{
           "TransactionContent" : "Work Info",
           "CreateUpdateFlag" : "Modify",
           "OriginatingSystem" : "Splunk",
           "AssigneeTicketNumber" : \"""" + INC  + """\",
           "WorkInfoSummary" : "Attachment",
           "WorkInfoNotes" : "Alert Results Attached",
           "FileAttachmentData1" : \"""" + encoded + """\",
           "FileAttachmentName1" : "Results.csv"          
          }"""

      LOG("INFO  sendmodalert - Formating_Results() -- Returning XML_Context Formatted")    
      LOG("INFO  sendmodalert - Formating_Results() -- Finished")    
      LOG("--------------------- XML Context To Be Sent ------------------ " + "\n" + XML_Context)
      return XML_Context
   except:
      LOG("ERROR  sendmodalert - Formating_Results() Error")   
      fh.close()
      exit()
#
#  +--------------------------------------------------------------------------------------+
#  | Function: RestRequest()					                                          |
#  |					       		                                                      |
#  | Sends XML String to OMI Using POST Requests                                          |
#  | >> Arguments: data          			                                          |
#  +--------------------------------------------------------------------------------------+
#

def RestRequest(data):
   LOG("INFO  sendmodalert - RestRequest() -- Started")
   try:
      requests.packages.urllib3.disable_warnings()
      
      #------------- Prod ----------------#
      url=<API System URL>
      username = <Username>
      password = <Password>

      Auth = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
      headers = {'Content-type': 'application/json', 'Authorization': 'Basic ' + Auth}
      LOG("INFO  sendmodalert - RestRequest() -- Sending POST Request")
      response = requests.post(url, verify=False,data = data, headers = headers)
      LOG("INFO  sendmodalert - RestRequest() -- Recieving Ack")
      #LOG("Status = " + str(response.status_code))
      LOG("Status = " + str(response.status_code) + "\n Content = \n" + str(response.text))
      return response.text
   except:
      LOG("ERROR  sendmodalert - RestRequest() Error")
      fh.close()
      exit()

def Email(TicketSummary,TicketNotes,WorkInfoSummary,WorkInfoNotes,Priority,WorkInfoAttachResults,INC,email,search_name):
    LOG("DEBUG  sendmodalert - Email() -- Started") 
    if WorkInfoAttachResults =="1":
        LOG("DEBUG  sendmodalert - Email() -- WorkInfoAttachResults If True")
        WorkInfoAttachResults="Alert Results attached to Ticket's Work-info Attachments"
    else:
        LOG("DEBUG  sendmodalert - Email() -- WorkInfoAttachResults If Flase")
        WorkInfoAttachResults=""
    LOG("DEBUG  sendmodalert - Email() -- getting hostname")
    hostname=socket.gethostname()
    LOG("DEBUG  sendmodalert - Email() -- Hostname: "+hostname)
    LOG("DEBUG  sendmodalert - Email() -- Formatting MSG")
    m="""From: noreply@SPLUNK
To: """ + str(email)  + """
Subject: SplunkAlert: """ +str(search_name)+ """ raised P"""+str(Priority)+""" ticket ["""+str(INC)+"""].
  
Hello, 
     
Kindly be informed that a Remedy Ticket with number [ """ + str(INC)  + """ ] has been raised with Priority [ P""" + str(Priority)  + """ ] for Splunk Alert [ """ + str(search_name)  + """  ] including the following info: 
         
Summary:
""" + str(TicketSummary)  + """
        
Notes:
""" + str(TicketNotes)  + """
         
Work-Info Summary:
""" + str(WorkInfoSummary)  + """
         
Work-Info Notes:
""" + str(WorkInfoNotes)  + """
         
""" + str(WorkInfoAttachResults)  + """
         
THIS IS AN AUTOMATED MESSAGE - PLEASE DO NOT REPLY DIRECTLY TO THIS EMAIL
For Support:
-	Please Contact : [ <Email> ]
         
Thank You
Best Regards,
Splunk's Remedy Ticket Alert Action
""" + str(hostname)  + """
.
"""

    LOG("DEBUG  sendmodalert - Email() -- MSG: "+m)

    LOG("DEBUG  sendmodalert - Email() -- Connecting to server")
    server = smtplib.SMTP(<Mail Server IP>, <Mail Server Port>)
    LOG("DEBUG  sendmodalert - Email() -- Server Connectted")
    #Send the mail
    LOG("DEBUG  sendmodalert - Email() -- Start Sending")
    server.sendmail("noreply@SPLUNK", email, m)
    LOG("DEBUG  sendmodalert - Email() -- MSG Sent")



#
#  +--------------------------------------------------------------------------------------+
#  | Function: Main()					                                                  |
#  |					       		                                                      |
#  | Responsible for running all functions in a logical sequence                          |
#  +--------------------------------------------------------------------------------------+
#

def Main():
    try:
       LOG("INFO  sendmodalert - Main() -- Started")
       LOG("INFO  sendmodalert - Main() -- Starting Capture_Retrieved_Results()")
       TicketSummary, TicketNotes, WorkInfoSummary, WorkInfoNotes, Priority, TroubleSubject, AssigneeArea, NotesAttachResults, SendMailNotification, EmailAddress, sid, search_name, app, owner, results_link, result, results_file, user_agent,WorkInfoAttachResults = Capture_Retrieved_Results()
       LOG("INFO  sendmodalert - Main() -- App : " + str(app))
       LOG("INFO  sendmodalert - Main() -- Owner : " + str(owner))
       LOG("INFO  sendmodalert - Main() -- SID : " + str(sid))
       LOG("INFO  sendmodalert - Main() -- Search Name : " + str(search_name))
       LOG("INFO  sendmodalert - Main() -- Starting Handling_Retrieved_Results()")
       #TicketSummary=re.sub('[^ a-zA-Z0-9]','',TicketSummary)
       #TicketNotes=re.sub('[^ a-zA-Z0-9]','',TicketNotes)
       #WorkInfoSummary=re.sub('[^ a-zA-Z0-9]','',WorkInfoSummary)
       #WorkInfoNotes=re.sub('[^ a-zA-Z0-9]','',WorkInfoNotes)
       #Retrieved_Results_As_List = Handling_Retrieved_Results(results)
       Retrieved_Results_As_List = Handling_Retrieved_Results(results_file)
       #counter="0"
       #header=[]
       #data=[]
       #for row in Retrieved_Results_As_List:
       #    if counter == "0":
       #        header.append(row)
       #        counter="1"
       #    else:
       #        data.append(row)
       #LOG("Deubg -- "+str(Retrieved_Results_As_List))
       INC="Dummy"
       LOG("INFO  sendmodalert - Main() -- Starting Formating_Results()")
       XMLContext = Formating_Results(TicketSummary, TicketNotes, WorkInfoSummary, WorkInfoNotes, Priority, TroubleSubject, AssigneeArea, search_name, NotesAttachResults, Retrieved_Results_As_List,results_file,WorkInfoAttachResults,"Creation",INC)
       #LOG("Deubg -- "+str(XmLContext))
       LOG("INFO  sendmodalert - Main() -- Starting RestRequest()")
       ResponseContent=RestRequest(XMLContext)
       words = ResponseContent.split()
       ProcessResult = [s for s in words if "ProcessResult" in s]
       RequestNumber = [s for s in words if "RequestNumber" in s]
       Status=str(ProcessResult[0]).split(">")[1].split("<")[0]
       INC=str(RequestNumber[0]).split(">")[1].split("<")[0]
       LOG(Status)
       LOG(INC)

       if WorkInfoAttachResults == "1":
           LOG("DEBUG  sendmodalert - Main() ---- In If Function for WorkInfoAttachResults: "+WorkInfoAttachResults)
           XMLContext = Formating_Results(TicketSummary, TicketNotes, WorkInfoSummary, WorkInfoNotes, Priority, TroubleSubject, AssigneeArea, search_name, NotesAttachResults, Retrieved_Results_As_List,results_file,WorkInfoAttachResults,"WINFO",INC)
           LOG("INFO  sendmodalert - Main() -- Starting RestRequest()")
           ResponseContent=RestRequest(XMLContext)
       LOG("DEBUG  sendmodalert - Main() ----SendMailNotification: "+SendMailNotification)
       if SendMailNotification == "1":
           LOG("DEBUG  sendmodalert - Main() ---- In If Function for Mail Notify")
           Email(TicketSummary,TicketNotes,WorkInfoSummary,WorkInfoNotes,Priority,WorkInfoAttachResults,INC,EmailAddress,search_name[0])       
       LOG("INFO  sendmodalert - Main() ---- Finished")
       LOG("INFO  sendmodalert - Main() ---- Closing LOG File ... ")
    except:
       LOG("ERROR  sendmodalert - MainLoop() Error")
    fh.close()
fh = open("./CustomAlertActionLOG","a")
Main()
