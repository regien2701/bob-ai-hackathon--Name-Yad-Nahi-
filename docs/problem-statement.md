# Problem Statement

## Background

Modern enterprise Security Operations Centres (SOCs) are inundated with data.
A mid-sized organisation typically deploys a dozen or more security tools — SIEMs,
endpoint detection platforms, network intrusion detection systems, cloud security
posture managers, and threat-intelligence feeds — each of which generates its own
stream of alerts. On a typical day a single SOC may receive thousands of raw
security events. Analysts are expected to review, triage, and respond to all of
them, often within tight service-level windows.

The tools that generate these alerts operate independently. Each tool has its own
severity vocabulary, its own alert schema, and no knowledge of what any other tool
has already flagged. As a result, the same underlying attack campaign can appear as
dozens of disconnected, differently-named alerts scattered across multiple queues,
with no indication that they share a root cause.

## The Problem

SOC analysts face three compounding problems simultaneously:

1. **Volume and noise.** The majority of alerts in any real SOC are false positives
   or low-signal informational events — estimates in the industry place the false-
   positive rate between 40 % and 70 % depending on the environment. Analysts must
   manually review each alert to determine its validity, consuming time that could
   be spent investigating confirmed threats.

2. **Lack of correlation.** When a threat actor performs a multi-stage attack —
   reconnaissance, credential access, lateral movement, and exfiltration — each
   stage may produce alerts in different tools. Without automated correlation those
   alerts sit in separate queues. Analysts see individual data points rather than a
   coherent attack narrative, making it extremely difficult to understand the full
   scope of an intrusion before it is too late.

3. **No executive-level briefing.** Security commanders and incident managers need
   a rapid, plain-language summary of what is happening and what action is required.
   Raw alert tables are not suitable for this purpose. Producing a briefing manually
   requires an analyst to synthesise information across many records, which takes
   time that is not available during an active incident.

## Who Is Affected

- **Tier-1 SOC analysts** who perform initial alert triage — they are the primary
  victims of alert fatigue and false-positive overload.
- **Tier-2 and Tier-3 incident responders** who investigate confirmed threats —
  they lose hours reconstructing attack timelines that could have been correlated
  automatically.
- **Security commanders and CISOs** who need to make rapid resource decisions during
  incidents — they currently depend on analysts to produce briefings by hand.
- **Organisations of all sizes** that cannot afford large analyst teams and therefore
  need automation to extend the capacity of every individual analyst on their roster.

## Why It Matters

The cost of delayed threat detection and poor alert management is concrete:

- The industry average dwell time for an attacker before detection is measured in
  days or weeks. Every hour of analyst time spent on false positives is an hour not
  spent reducing that dwell time.
- Ransomware campaigns, data exfiltration events, and supply-chain compromises all
  exploit the window between initial access and detection. Faster correlation directly
  reduces the blast radius of a successful intrusion.
- Alert fatigue causes burnout. Analyst turnover in the SOC industry is among the
  highest of any technical role, and understaffed SOCs are demonstrably slower to
  detect and contain incidents.

## Why Existing Solutions Fall Short

Enterprise SIEM platforms such as Splunk and IBM QRadar provide correlation rules,
but they require extensive custom tuning by experienced engineers, cost hundreds of
thousands of dollars annually, and still produce alert queues that analysts must work
through manually. Smaller organisations cannot afford them at all.

Managed detection-and-response (MDR) services address some of the volume problem
but add latency through a third-party intermediary and do not provide the commander-
level BLUF briefings that are essential during fast-moving incidents.

No widely available, affordable tool combines automated multi-source ingestion,
transparent explainable scoring, MITRE ATT&CK mapping, correlation, and AI-generated
plain-language incident summaries in a single lightweight application that a team can
deploy and demo without a cloud budget or a dedicated DevOps engineer.

## The D2 Challenge

IBM Bob AI Hackathon 2026 Problem D2 asks teams to build a **Threat Intelligence
Correlation and Alert Prioritisation Assistant** that demonstrates how AI can help
SOC analysts cut through noise, identify genuine threats faster, and deliver
actionable intelligence to decision-makers. The challenge specifically calls for:

- Multi-source alert ingestion and normalisation
- Risk scoring and priority classification
- Alert correlation into incidents
- MITRE ATT&CK technique identification
- AI-generated investigation summaries using IBM watsonx.ai
- A dashboard suitable for both analysts and commanders
