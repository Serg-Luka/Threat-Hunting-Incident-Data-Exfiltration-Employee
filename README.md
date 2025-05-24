# Table of Contents

- 🌟 **[1. Threat Hunting Scope](#threat-hunting-scope)**
- 🌟 **[2. Timeline Summary and Findings](#timeline-summary-and-findings)**
  - [2.1 Initial Investigation](#21-initial-investigation)
  - [2.2 Detailed Analysis](#22-detailed-analysis)
  - [2.3 Network Exfiltration Check](#23-network-exfiltration-check)
  - [2.4 USB Connection Investigation](#24-usb-connection-investigation)
- 🌟 **[3. KQL Detection Rule](#3-kql-detection-rule)**
- 🌟 **[4. Investigation Conclusion](#4-investigation-conclusion)**
- 🌟 **[5. Relevant MITRE ATT&CK TTPs](#5-relevant-mitre-attck-ttps)**
- 🌟 **[6. Response and Mitigation Steps](#6-response-and-mitigation-steps)**
  - [6.1 Response Actions](#61-response-actions)
  - [6.2 Mitigation Strategies](#62-mitigation-strategies)

<a name="threat-hunting-scope"></a>
# 1.	Threat Hunting Scope

**Goal:** An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company (insider risk). Your task is to investigate John's activities on his corporate device (windows-target-1) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

**Activity:** John, as an administrator on his device, has unrestricted access to applications and may attempt to archive or compress sensitive information before transferring it to a private drive or other location.

<a name="timeline-summary-and-findings"></a>
# 2.	Timeline Summary and Findings

## 2.1 Initial Investigation

I queried DeviceFileEvents in Microsoft Defender for Endpoint and observed frequent creation of .zip files within a folder named "backup".

<img src="https://i.imgur.com/6VI6N4l.png">

**KQL Query Used:**

```
DeviceFileEvents
| where DeviceName == "windows-target-1"
| where FileName contains ".zip"
| order by Timestamp desc
```

## 2.2 Detailed Analysis

I identified a zip file creation event and noted its timestamp. Using that, I searched within the DeviceProcessEvents for any related activity occurring within a two-minute window before and after the archive was created. During this timeframe, I discovered that a PowerShell script had silently installed 7-Zip and subsequently used it to compress employee data into an archive.

<img src="https://i.imgur.com/tnPyWwL.png">

**KQL Query Used:**

```
let VMName = "windows-target-1";
let SpecificTime = datetime(2025-04-11T20:49:59.6464336Z);
DeviceProcessEvents
| where Timestamp between ((SpecificTime -2m)..(SpecificTime +2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

## 2.3 Network Exfiltration Check

I examined the same time window for any signs of data exfiltration from the network but found no logs indicating such activity.

<img src="https://i.imgur.com/mXdk8Zn.png">

**KQL Query Used:**

```
let VMName = "windows-target-1";
let SpecificTime = datetime(2025-04-11T20:49:59.6464336Z);
DeviceNetworkEvents
| where Timestamp between ((SpecificTime -2m)..(SpecificTime +2m))
| where DeviceName == VMName
| order by Timestamp desc
```

## 2.4 USB Connection Investigation

Since there was no evidence of the zip file being transmitted over the network, I decided to investigate recent USB connections to determine if the file may have been transferred via a USB device instead of email.

<img src="https://i.imgur.com/8EufX3E.png">

**KQL Query Used:**

```
DeviceEvents
| where DeviceName == "windows-target-1"
| where ActionType == "USBDevicePlugIn"
| where Timestamp > ago(7d) 
| order by Timestamp desc
```

#  3. KQL Detection Rule

I created a hypothetical detection rule for this lab to flag any user who generates 2 or more zip files within a 1-hour window. It excludes system-level activity and focuses on user-initiated actions. In a real-world scenario, this rule would be refined in consultation with management to account for users who routinely create zip files as part of their normal duties. This approach helps surface unusual activity that may indicate an attempt to exfiltrate data. I would also normally include a wider range of compressed file formats, but for the sake of this lab, I focused solely on .zip files.

```
DeviceFileEvents
| where FileName endswith ".zip"
| where RequestAccountName != "SYSTEM"
| where Timestamp > ago(1h)
| summarize ZipFileActivity = count(), Timestamp = max(Timestamp), ReportId = any(ReportId), DeviceId = any(DeviceId) by RequestAccountName
| where ZipFileActivity >= 2
```

# 4. Investigation Conclusion

Since no USB connections were detected and there was no evidence of the zip file being transmitted over the network, it can be ruled out that the file was transferred from the targeted machine via either method.

I reported the findings to the manager, highlighting the automated creation of the archive and noting that there were no immediate signs of data exfiltration. The device was isolated pending further instructions. I also shared a suggested detection rule to help flag similar activity in the future.

# 5. Relevant MITRE ATT&CK TTPs

| Tactic                     | Technique                            | Description                                                                                          | Detection                                                                 |
|----------------------------|--------------------------------------|------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| Initial Access             | Valid Accounts (T1078)              | John has administrative access to the device, which allows him to install and use applications without restriction. | Monitor for unusual account logins or escalated privileges.               |
| Execution                  | PowerShell (T1059.001)              | A PowerShell script was used to install 7-Zip and compress data into an archive.                     | Detect PowerShell execution, especially for commands that involve downloading and installing tools. |
| Persistence                | Startup Items (T1547)               | The installation of 7-Zip through a PowerShell script could potentially be part of a persistence mechanism. | Monitor for registry or scheduled task modifications that could indicate persistence strategies. |
| Collection                 | Data from Information Repositories (T1213) | John attempted to collect sensitive company data by archiving files into a zip archive.              | Monitor for file and folder activity, particularly with sensitive data.   |
| Exfiltration (Investigated)| Exfiltration Over Network (T1041)   | Investigated network events to check for signs of exfiltration but found no evidence of data being transferred over the network. | No evidence of exfiltration over network was found during the investigation. |
| Exfiltration (Investigated)| Exfiltration Over USB (T1052)       | Investigated USB connections to determine if the file was transferred via a USB device but found no devices connected within the last 7 days. | No USB connections were found during the investigation.                   |
| Impact                     | Data Destruction (T1485)            | Although not directly observed, John could have intended to delete or corrupt sensitive data after exfiltrating it. | Monitor for file deletion or overwriting of sensitive data after exfiltration. |

# 6. Response and Mitigation Steps

## 6.1 Response Actions

1.	Isolate the Device: Prevent further unauthorised actions by keeping the device isolated.
2.	Review Logs: Analyse logs for suspicious activities, focusing on the creation of archives and any related processes.
3.	Consult HR/Legal: Work with HR and legal teams for appropriate actions regarding the employee.

## 6.2 Mitigation Strategies

1.	Limit Admin Access: Restrict admin privileges to only necessary personnel.
2.	Enhance Monitoring: Strengthen endpoint monitoring to detect suspicious activity early.
3.	Implement DLP: Enforce data loss prevention policies to prevent unauthorised data transfers.

