# Windows CLI inc PowerShell (Complete)
Introduction to Windows Command Line (Complete)  
Windows Fundermentals (Complete)  

## Useful Commands 
**doskey /history** - lists command history  
**tree /f** - lists directory structure with files. omit /f for just folders.  
**rd /s** - deletes directory /s is for sub directorys  
**more /s** - reads a file and scrunches the line spacing  
**fine /i** - use this in commands to find text. ie find /i "string" < password.txt  

**set DCIP=172.16.5.2** - sets a environmental variable (temporaly), in this case DCIP Address  
**setx DCIP=172.16.5.2** - sets a environmental variable (permanently), in this case DCIP Address
**echo %DCIP%** - displays enviromental variable 



## Good Resources 
- https://ss64.com/nt/ -


  




### Definitions
**Incident** is an event with a negative consequence. 
**Security Incident** Compromise of service or system confidentiality, integrity, or availability.


## Incident Handling Process  

### Preperation Stage ##
Establishment of **incident handling capability** within the organization. And the ability to protect against and prevent security incidents by **implementing appropriate protective measures**. Skilled incident handling team members and a train workforce. 


**Clear Policies & Documentation**
> Contact information and roles of relevant teams and external assistance -- eg. incident handling team members, legal and compliance, managment, support, communications, law enforcment, facilities, service providers.
>
> Policies, Plans and Procedures -- Incident Response, Information, Cheat Sheets, etc.
>
> Baselines -- golden image and/or clean state of environment.
>
> Technology Diagrams & Designs -- Network, Artechiet, etc
>
> Asset Managment -- Databses,
>
> User and Privledge Account processes -- on-demand when necessary for highest privledges.
>
>   ..


**Tools (Software & Hardware)**
> Forensic laptops -- preserve disk images and log files, perform data analysis, and investigate without any restrictions.
>
> Security tools -- Log analysis and capture for toos items like Network, Workstations, Access, Files, Databases.
>
> Jump Bag -- Off network bag or box containing tools, pre printed forms and documents needed for investigating, evidence holding, contats, tools, hardware, etc etc.
>
> ...  

**Protective Measures**
> Protection Tools -- DMARC email protection  --  Vulnerabilty Scanning, Active Directory
>
> Protective Configurations -- Endpoint Hardening (& EDR) CIS and Microsoft baselines -- Firewalls, DMZ, 
>
> User and Identity Management -- Password/MFA Requirements
>
> Training and Awareness --  Purple Teaming Excercises -- PenTesting



### Detection & Analysis Stage###
The detection & analysis phase involves all aspects of detecting an incident.  

Threats are introduced to the organization via an infinite amount of attack vectors, and their detection can come from sources such as:
- An employee that notices abnormal behavior
- An alert from one of our tools (EDR, IDS, Firewall, SIEM, etc.)
- Threat hunting activities
- A third-party notification informing us that they discovered signs of our organization being compromised


**Initial Investigation**
> Aim to collect as much information as possible at this stage about the following:
> 
> Date/Time the incident was reported.
> 
> Who detected and/or who reported it?
> 
> How was the incident detected?
> 
> What was the incident? Phishing? System unavailability? etc.
> 
> Assemble a list of impacted systems (if relevant)
> 
> Document who has accessed the impacted systems and what actions have been taken. Make a note of whether this is an ongoing incident or the suspicious activity has been stopped
> 
> Physical location, operating systems, IP addresses and hostnames, system owner, system's purpose, current state of the system
>
> (If malware is involved) List of IP addresses, time and date of detection, type of malware, systems impacted, export of malicious files with forensic information on them (such as hashes, copies of the files, etc.)
>
> ...  


**Incident Severity & Extent Questions**  
>   What is the exploitation impact?  
    What are the exploitation requirements?  
    Can any business-critical systems be affected by the incident?  
    Are there any suggested remediation steps?  
    How many systems have been impacted?  
    Is the exploit being used in the wild?  
    Does the exploit have any worm-like capabilities?  


**Incident Confidentiality & Communication** - Information gathered should be kept on a need-to-know basis, unless applicable laws or a management decision instruct us otherwise.  

**Investigation Cycle** - Indicator of Compromise -- Identification Of New Leads & Impacted Systems -- Data Collection & Analysis From The New Leads & Impacted Systems


## Containment, Eradication, & Recovery Stage ##
When the investigation is complete it is time to enter the containment stage to prevent the incident from causing more damage.


**Containment**
> To stop the attack or breach
>
> short-term containment - network isolation or removal. Stopping the attack but not removing evidence as we may do when shutting down.
>  
> long-term containment - firewalling, patching, changing passwords, shutting down.
>
> ..

**Eradication**
> To remove/fix the attack or breach
>
> Some of the activities in this stage include removing the detected malware from systems, rebuilding some systems, and restoring others from backup.
>
> ..

**Recovery**
> Bring systems back online to normal
>
> Verify that a system is in fact working as expected.
>
> Increase monitoring for suspecious events - unusual logins, behaviours, logs
> ..

## Post-Incident Activity Stage ##
Document the incident and improve future capabilities.

**Reporting**
> 
    What happened and when?
    Performance of the team dealing with the incident in regard to plans, playbooks, policies, and procedures
    Did the business provide the necessary information and respond promptly to aid in handling the incident in an efficient manner? What can be improved?
    What actions have been implemented to contain and eradicate the incident?
    What preventive measures should be put in place to prevent similar incidents in the future?
    What tools and resources are needed to detect and analyze similar incidents in the future?
>



## Useful Links ##  
NIST Computer Security
Incident Handling Guide - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf  

