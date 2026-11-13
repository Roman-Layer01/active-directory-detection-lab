# Detection Case Study — AI-Assisted Kerberos Authentication Failure Detection

**Project:** THE.WIRED Active Directory Detection Lab  
**Platform:** VMware Workstation / Windows Server / Elastic Security  
**Detection:** Kerberos Preauthentication Failures  
**Windows Event ID:** 4771  
**Failure Code:** `0x18` — Incorrect Password  
**Development Approach:** AI-assisted detection engineering with Codex  
**Validation Status:** Successfully triggered in controlled testing  
**Date:** November 2026

---

## Executive Summary

This case study documents the development and validation of a Kerberos authentication failure detection using Codex to assist with infrastructure diagnostics, security telemetry investigation, and Elastic Security rule creation.

The work extended an existing Active Directory and Elastic SIEM laboratory rather than introducing an independent environment.

During the investigation, a significant telemetry gap was identified: the Domain Controller was not forwarding Windows security events into Elasticsearch.

After configuring the required collection and auditing, I developed a detection for repeated Kerberos preauthentication failures and verified that controlled authentication attempts generated a Medium-severity alert.

The project demonstrates AI-assisted security engineering with human supervision, technical validation, and awareness of operational security boundaries.

## Lab Architecture

The existing THE.WIRED environment consists of:

| System | Function |
|---|---|
| Windows Server | Active Directory Domain Controller and DNS |
| Windows 11 | Domain-joined test workstation |
| Ubuntu Linux | Elasticsearch, Kibana, and Fleet |
| VMware Workstation | Virtualization and lab networking |
| Codex | AI-assisted diagnostics and detection development |

The Windows 11 endpoint and Domain Controller provide different forms of authentication telemetry.

The endpoint was already collecting Windows Security, PowerShell, and Sysmon events.

The Domain Controller required additional telemetry configuration.

## Initial Assessment

Codex assisted with validating the lab environment.

The investigation confirmed:

- Active Directory Domain Services, DNS, and Netlogon were operational.
- The Windows 11 workstation maintained a valid domain secure channel.
- Sysmon and Elastic Agent were running on Windows 11.
- Elasticsearch and Kibana were accessible.
- Windows 11 security telemetry was searchable in Elasticsearch.
- The Domain Controller lacked equivalent Elastic Agent collection.

This represented a visibility gap for centralized identity monitoring.

## Domain Controller Telemetry Integration

A dedicated Fleet agent policy was created for Domain Controller event collection.

The collection and auditing work included:

1. Creating a separate Domain Controller policy in Fleet.
2. Configuring Windows Security, System, Application, and PowerShell event collection.
3. Enabling Kerberos and NTLM authentication failure auditing.
4. Enabling process creation auditing with command-line logging.
5. Preserving configuration backups.
6. Installing and enrolling Elastic Agent.
7. Validating healthy agent status and searchable event ingestion.

### Verification

After enrollment, the Domain Controller was successfully sending Windows events to Elasticsearch.

A 15-minute validation period included:

| Event ID | Observed count | Description |
|---|---:|---|
| 4624 | 73 | Successful logons |
| 4688 | 42 | Process creation |
| 4776 | 30 | Credential validation |

These counts represent one observed validation window, not ongoing baseline rates.

## Detection Objective

Detect repeated Kerberos preauthentication failures using an incorrect password against the same account from the same source IP.

This behavior can indicate:

- Password guessing
- Brute-force attempts
- Misconfigured services
- Stale credentials
- Repeated legitimate user errors

A repeated-failure alert is an investigation indicator, not proof of malicious activity.

## Detection Logic

The rule was configured around the following conditions:

| Parameter | Configuration |
|---|---|
| Windows event | 4771 |
| Kerberos failure code | `0x18` |
| Threshold | Three failures |
| Correlation keys | Account and source IP |
| Time window | Five minutes |
| Rule interval | One minute |
| Severity | Medium |
| Risk score | 47 |

### Conceptual Query

```kql
event.code: "4771" and winlog.event_data.Status: "0x18"
```

**Note:** This is illustrative KQL, not a verified export of the live Elastic detection rule. The actual threshold and field mappings should be documented from the exported configuration.

The rule's grouping behavior was intended to distinguish repeated failures for the same account and source rather than aggregating unrelated authentication errors.

## Controlled Validation

A designated lab test account was used to generate three authentication failures from the Windows 11 workstation.

The Domain Controller recorded the expected 4771 events with incorrect-password status `0x18`.

The test account remained unlocked.

Elastic subsequently generated a Medium-severity alert matching the new detection rule.

**Result: Detection successfully validated.**

This confirmed that the pipeline from Windows authentication activity through Domain Controller event logging, Elastic Agent ingestion, and Elastic Security alerting was functioning for the tested scenario.

## AI-Assisted Workflow

Codex supported several phases of the exercise:

**Infrastructure diagnostics:** Inspected VMware guest states, service health, remoting availability, and Elastic connectivity.

**Telemetry investigation:** Checked Windows logging configuration, identified the Domain Controller collection gap, and verified event delivery after remediation.

**Detection development:** Assisted with configuring a repeated Kerberos failure rule in Elastic Security.

**Validation:** Generated controlled authentication failures and verified resulting events.

**Human oversight:** Administrative access changes and other significant modifications were subject to explicit approval.

Codex accelerated the workflow, but the observed events and resulting alerts were used to validate the detection.

## Security Considerations

Administrative access was established using SSH key authentication and locally supplied Windows credentials rather than publishing passwords in prompts or source control.

The initial Windows remoting workflow used a privileged Domain Administrator account. This was functional in the isolated lab but was not a least-privilege implementation.

Future improvements should include dedicated restricted automation identities and more granular authorization.

The original environment also included NAT and an additional Windows 11 network adapter, so complete network isolation was not conclusively verified.

## Limitations

- The test used a single designated account and source.
- The detection was validated against controlled authentication failures.
- False-positive behavior has not been systematically measured.
- The exported live rule configuration is not yet included.
- This test does not establish detection of distributed password spraying across many accounts or sources.
- A 4771 failure does not prove unauthorized access occurred.
- Downstream successful authentication and logon correlation remain future work.

## Next Steps

Planned improvements:

- Export and sanitize the live Elastic detection rule.
- Include sanitized 4771 event evidence.
- Test legitimate repeated password mistakes.
- Implement a separate failed-authentication-followed-by-success correlation.
- Correlate Domain Controller authentication with endpoint activity.
- Explore source-IP enrichment where trustworthy location information is available.
- Develop reusable scripts to validate the detection against controlled test data.

## Conclusion

This exercise extended an existing Active Directory security lab by closing a Domain Controller telemetry gap and successfully validating a Kerberos authentication failure detection.

The project demonstrates practical identity monitoring, SIEM troubleshooting, AI-assisted detection engineering, and evidence-based validation.

The most important result was not simply creating a new rule. It was confirming that the required telemetry existed, flowed into Elastic, and generated the intended security alert under controlled conditions.

---

**Status:** Validated in a non-production cybersecurity laboratory.
