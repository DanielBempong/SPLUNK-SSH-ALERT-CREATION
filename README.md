# SPLUNK-SSH-ALERT-CREATION
Splunk SOC lab demonstrating successful SSH authentication detection, MITRE ATT&amp;CK T1078 mapping, scheduled alert configuration, and SOC investigation workflow.


# Splunk SSH Alert Creation – SOC Analyst Lab

## Project Overview

This project demonstrates how to create and configure a scheduled security detection alert in Splunk Enterprise to identify successful SSH authentication activity.

The lab uses Splunk Search Processing Language (SPL) to identify successful password-based SSH logins, enrich source IP addresses with geographic information, and configure a scheduled alert that checks for matching events every 15 minutes.

The detection is mapped to MITRE ATT&CK technique T1078 – Valid Accounts.

## Tools & Technologies

- Splunk Enterprise
- Search Processing Language (SPL)
- Linux SSH Authentication Logs
- Detection Engineering
- Scheduled Alert Configuration
- MITRE ATT&CK
- IP Geolocation Enrichment
- SOC Incident Triage

## Lab Environment

| Item | Configuration |
|---|---|
| Platform | Splunk Enterprise |
| Application | mydfir-splunk |
| Index | mydfir-lab1 |
| Host | linuxvm |
| Log Source | auth.log |
| Sourcetype | linux_auth_logs |
| Alert Name | Network - T1078 Successful SSH Authentication |
| Alert Type | Scheduled |
| Cron Schedule | */15 * * * * |
| Trigger Condition | Number of Results > 0 |
| Alert Action | Add to Triggered Alerts |

## Detection Objective

- Detect successful password-based SSH authentication.
- Identify the associated username, source IP, timestamp, and geographic context.
- Generate a scheduled alert every 15 minutes.
- Trigger an alert when one or more matching events are returned.
- Preserve triggered detections for SOC analyst review.

## SPL Detection Query

```spl
index="mydfir-lab1" host="linuxvm" source="auth.log" sourcetype="linux_auth_logs"
msg="Accepted Password"
| iplocation src_ip
| stats count by _time,user,Country,src_ip
```

## Investigation Findings

The successful SSH authentication search returned six events in the displayed January 7–8, 2024 time range.

The results included:

- Event timestamp
- Username
- Country
- Source IP address
- Event count

The search identifies successful password-based SSH authentication using the message value `Accepted Password`.

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | Network - T1078 Successful SSH Authentication |
| Alert Type | Scheduled |
| Cron Expression | */15 * * * * |
| Trigger Condition | Number of Results is > 0 |
| Action | Add to Triggered Alerts |
| Permissions | Shared in App |
| Owner | mydfir |
| Application | mydfir-splunk |

The cron expression `*/15 * * * *` schedules the detection to run every 15 minutes.

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Valid Accounts | T1078 | Successful authentication using an account |

**Security note:** A successful SSH login does not independently establish malicious activity. Analysts must validate the user, source IP, authentication context, and surrounding activity.

## SOC Analyst Investigation Workflow

1. Open the triggered alert.
2. Identify the authentication timestamp and username.
3. Review the source IP address.
4. Perform a +/- 5-minute search around the authentication event.
5. Use OSINT to obtain additional source-IP context.
6. Review other activity associated with the user and source IP.
7. Correlate authentication with process, network, privilege, and account activity.
8. Document findings and determine whether escalation or remediation is required.

## Recommended Detection Enhancements

- Correlate successful SSH logins with preceding failed authentication attempts.
- Add account context to distinguish normal administrative access from unusual activity.
- Investigate repeated successful logins from unexpected source IPs.
- Correlate authentication with process execution and privilege changes.
- Consider alert suppression or throttling to reduce duplicate notifications.
- Evaluate additional response actions after validation and testing.

## Project Evidence

See `Splunk_SSH_Alert_Creation_SOC_Report.pdf` for the complete lab walkthrough, SPL query, screenshots, alert configuration, trigger condition, permissions, and final detection settings.

## Skills Demonstrated

Splunk Enterprise | SPL | Linux SSH Authentication Analysis | Detection Engineering | Scheduled Alert Configuration | Cron Scheduling | MITRE ATT&CK T1078 | IP Geolocation | SOC Triage | Incident Investigation | Technical Documentation


