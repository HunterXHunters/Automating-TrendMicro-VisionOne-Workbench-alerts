# Automating TrendMicro VisionOne Workbench alerts: "Possible Spear Phishing Attack via Links"

In this script, we have picked VisionOne workbench alert with category "Possible Spear Phishing Attack via Links" in automating manual tasks which L1 team performing in process of triaging the alert. 

1. Intially, script fetches all workbench alerts and picks first alert as incident to be triaged for analysis

2. Script now compared the picked top 1 alert, compares if the model name is "Possible Spear Phishing Attack via Link" and if model name matches, it goes to next steps.

3. Script will extract uuid which will be required to pull suspicious Highlighted Requests from VisionOne OATs.

4. Script will now extract suspicious Highlighted Requests i.e. links in this workbench model using Observed Attack Techniques module in VisionOne.

5. Suspicious Highlighted Requests will be now send to VirusTotal for threat lookup.
#### Use-cases:
	1. If number of engines detected is 0: is not Malicious and needs no furthure actions.
	2. If number of engines detected is > 0 and <= 3: Maybe Malicious which requires manual investigation and if found abnormal, please add findings to VisionOne Suspicious Object list or add IoC to your respective security tools [if non-TM tools at Network, Email Gateway, etc.]
	3. If number of engines detected is > 4: is found Malicious and next steps follows as below.

6. If number of engines detected is > 4, we will follow the next steps in blocking them.

7. As part of containment stratergy, script will block suspicious Highlighted Requests in Suspicious Object Management module from Vision One Threat Intelligence.

8. Script will now update notes to selected workbench alert. Since it is workbench alert which get triggered after a threshold of same alerts, we do not insist to flag the workbench alert to closure and required L2 comments.
