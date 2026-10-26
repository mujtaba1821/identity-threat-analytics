"""Rule catalog: plain-English logic plus SIEM-ready translations.

KQL targets Microsoft Sentinel (Entra ID SigninLogs / AuditLogs).
ES|QL targets Elastic Security with the Okta integration (ECS fields).
Sigma uses the v2 specification, including correlation rules for thresholds.
"""

RULES = {
"BF": dict(name="Brute Force", technique="T1110.001", tactic="Credential Access",
  logic="10+ wrong passwords for one account from one IP within 10 minutes.",
  tuning="Corporate egress IPs need 25+ failures. Office lockouts were the only false positives.",
  sigma="""title: Brute Force Against Single Account
id: 6f1e2a40-ita-bf
status: experimental
logsource: {product: azure, service: signinlogs}
detection:
  selection: {ResultType: 50126}   # invalid username or password
  condition: selection
---
title: Brute Force Threshold
correlation:
  type: event_count
  rules: [6f1e2a40-ita-bf]
  group-by: [UserPrincipalName, IPAddress]
  timespan: 10m
  condition: {gte: 10}
tags: [attack.credential-access, attack.t1110.001]
level: high""",
  kql="""SigninLogs
| where ResultType == 50126
| summarize Failures = count(), First = min(TimeGenerated)
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| extend IsCorp = ipv4_is_in_any_range(IPAddress, dynamic(["198.51.100.0/24"]))
| where (IsCorp and Failures >= 25) or (not(IsCorp) and Failures >= 10)""",
  esql="""FROM logs-okta.system-*
| WHERE event.action == "user.session.start" AND event.outcome == "failure"
    AND okta.outcome.reason == "INVALID_CREDENTIALS"
| EVAL bucket = DATE_TRUNC(10 minutes, @timestamp)
| STATS failures = COUNT(*) BY user.name, source.ip, bucket
| WHERE failures >= 10"""),

"PS": dict(name="Password Spraying", technique="T1110.003", tactic="Credential Access",
  logic="One external /24 subnet fails against 10+ distinct accounts within 3 hours, with 80%+ of its sign-ins failing.",
  tuning="v1 grouped by single IP and missed a spray rotated across 4 IPs. Grouping by /24 caught it; excluding corporate egress removed password-expiry noise.",
  sigma="""title: Password Spray Failure
id: 2b7c9d11-ita-ps
logsource: {product: azure, service: signinlogs}
detection:
  selection: {ResultType: 50126}
  filter_corp: {IPAddress|cidr: 198.51.100.0/24}
  condition: selection and not filter_corp
---
title: Password Spray Distinct Accounts
correlation:
  type: value_count
  rules: [2b7c9d11-ita-ps]
  group-by: [IPAddress]
  timespan: 3h
  condition: {field: UserPrincipalName, gte: 10}
tags: [attack.credential-access, attack.t1110.003]
level: high""",
  kql="""SigninLogs
| where not(ipv4_is_in_any_range(IPAddress, dynamic(["198.51.100.0/24"])))
| extend Subnet = format_ipv4_mask(IPAddress, 24)
| summarize Accounts = dcountif(UserPrincipalName, ResultType == 50126),
            FailRatio = countif(ResultType != 0) * 1.0 / count(),
            IPs = make_set(IPAddress), Hits = make_set_if(UserPrincipalName, ResultType == 0)
    by Subnet, bin(TimeGenerated, 3h)
| where Accounts >= 10 and FailRatio >= 0.8""",
  esql="""FROM logs-okta.system-*
| WHERE event.action == "user.session.start"
| EVAL subnet = CONCAT(SUBSTRING(TO_STRING(source.ip), 0, LOCATE(TO_STRING(source.ip), ".", 9)), ".0/24")
| STATS accounts = COUNT_DISTINCT(user.name), fails = COUNT(event.outcome == "failure" OR NULL), total = COUNT(*)
    BY subnet, bucket = DATE_TRUNC(3 hours, @timestamp)
| WHERE accounts >= 10 AND fails * 1.0 / total >= 0.8"""),

"PSS": dict(name="Spray Success", technique="T1110.003 → T1078", tactic="Initial Access",
  logic="Any successful sign-in from a source that is password spraying. The spray worked.",
  tuning="Escalation of Password Spraying; inherits its tuning.",
  sigma="# Expressed as a join on the spray correlation output (see KQL).",
  kql="""let Sprayers = SigninLogs
| extend Subnet = format_ipv4_mask(IPAddress, 24)
| summarize Accounts = dcountif(UserPrincipalName, ResultType == 50126) by Subnet
| where Accounts >= 10;
SigninLogs
| where ResultType == 0
| extend Subnet = format_ipv4_mask(IPAddress, 24)
| join kind=inner Sprayers on Subnet""",
  esql="# Run Password Spraying, then FROM logs-okta.system-* | WHERE event.outcome == \"success\" AND source.ip IN (<spraying IPs>)"),

"IT": dict(name="Impossible Travel", technique="T1078.004", tactic="Initial Access",
  logic="Consecutive successful sign-ins whose distance over time needs more than 900 km/h.",
  tuning="Skip pairs involving the corporate VPN (Frankfurt exit node) or mobile carrier IPs, whose geolocation reflects the carrier hub, not the user.",
  sigma="# Stateful (needs previous event per user). Use the KQL / ES|QL versions.",
  kql="""SigninLogs
| where ResultType == 0
| where not(ipv4_is_in_any_range(IPAddress, dynamic(["198.51.100.200/31","100.64.0.0/10"])))
| extend Lat = toreal(LocationDetails.geoCoordinates.latitude), Lon = toreal(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevLat = prev(Lat), PrevLon = prev(Lon), PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| extend Km = geo_distance_2points(Lon, Lat, PrevLon, PrevLat) / 1000,
         Hours = max_of(datetime_diff('minute', TimeGenerated, PrevTime), 1) / 60.0
| where Km / Hours > 900""",
  esql="# ES|QL has no row-lag function yet; use the Elastic 'Impossible Travel' ML job or an EQL sequence by user.name."),

"MF": dict(name="MFA Fatigue", technique="T1621", tactic="Credential Access",
  logic="An MFA push is approved after 5+ denied pushes for the same user in 20 minutes.",
  tuning="No tuning needed. Accidental single denials never reach 5.",
  sigma="""title: MFA Push Denied
id: 9a0f4c22-ita-mf
logsource: {product: azure, service: signinlogs}
detection:
  selection: {ResultType: 500121}
  condition: selection
---
title: MFA Fatigue
correlation:
  type: event_count
  rules: [9a0f4c22-ita-mf]
  group-by: [UserPrincipalName]
  timespan: 20m
  condition: {gte: 5}
tags: [attack.credential-access, attack.t1621]
level: critical""",
  kql="""let Denials = SigninLogs
| where ResultType == 500121
| summarize Denied = count(), LastDeny = max(TimeGenerated) by UserPrincipalName, bin(TimeGenerated, 20m)
| where Denied >= 5;
SigninLogs
| where ResultType == 0 and AuthenticationRequirement == "multiFactorAuthentication"
| join kind=inner Denials on UserPrincipalName
| where TimeGenerated between (LastDeny .. LastDeny + 10m)""",
  esql="""FROM logs-okta.system-*
| WHERE event.action == "user.mfa.okta_verify.deny_push"
| STATS denied = COUNT(*) BY user.name, bucket = DATE_TRUNC(20 minutes, @timestamp)
| WHERE denied >= 5"""),

"LA": dict(name="Legacy Auth Login", technique="T1078.004", tactic="Defense Evasion",
  logic="Successful IMAP/POP/SMTP basic-auth sign-in from a non-corporate IP. Legacy protocols cannot do MFA.",
  tuning="v1 alerted on the scan-to-email service account every day. Restricting to external IPs removed it.",
  sigma="""title: Legacy Authentication From External IP
logsource: {product: azure, service: signinlogs}
detection:
  selection:
    ResultType: 0
    ClientAppUsed: [IMAP4, POP3, Authenticated SMTP, Exchange ActiveSync, Other clients]
  filter_corp: {IPAddress|cidr: 198.51.100.0/24}
  condition: selection and not filter_corp
tags: [attack.defense-evasion, attack.t1078.004]
level: high""",
  kql="""SigninLogs
| where ResultType == 0
| where ClientAppUsed in ("IMAP4","POP3","Authenticated SMTP","Exchange ActiveSync","Other clients")
| where not(ipv4_is_in_any_range(IPAddress, dynamic(["198.51.100.0/24"])))""",
  esql="""FROM logs-o365.audit-*
| WHERE event.outcome == "success" AND o365.audit.ExtendedProperties.UserAgent RLIKE ".*(IMAP|POP|SMTP).*"
    AND NOT CIDR_MATCH(source.ip, "198.51.100.0/24")"""),

"DA": dict(name="Terminated / Dormant Account", technique="T1078.004", tactic="Persistence",
  logic="Any sign-in to an account HR lists as terminated, or the first sign-in after 30+ quiet days.",
  tuning="v1 used a 14-day gap and flagged an employee back from leave. Joining the HR directory gives a precise signal.",
  sigma="# Requires an HR/IdP directory lookup; see KQL with a watchlist.",
  kql="""let Terminated = _GetWatchlist('TerminatedUsers') | project UserPrincipalName = SearchKey, EndDate = todatetime(EndDate);
SigninLogs
| where ResultType == 0
| join kind=inner Terminated on UserPrincipalName
| where TimeGenerated > EndDate""",
  esql="""FROM logs-okta.system-*
| WHERE event.outcome == "success"
| ENRICH hr-terminated-users ON user.name WITH end_date
| WHERE end_date IS NOT NULL AND @timestamp > end_date"""),

"NC": dict(name="New Country + New Device", technique="T1078", tactic="Initial Access",
  logic="Successful sign-in from a country never seen for this user, on a device never seen for this user.",
  tuning="v1 used new country alone and flagged every business trip and VPN exit. Travelers bring their own laptop, attackers do not. New hires with no history are skipped.",
  sigma="# Stateful baseline per user; see KQL.",
  kql="""let Baseline = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(1d)) and ResultType == 0
| summarize Countries = make_set(tostring(LocationDetails.countryOrRegion)),
            Devices = make_set(tostring(DeviceDetail.deviceId)) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == 0
| join kind=inner Baseline on UserPrincipalName
| where not(set_has_element(Countries, tostring(LocationDetails.countryOrRegion)))
    and not(set_has_element(Devices, tostring(DeviceDetail.deviceId)))""",
  esql="# Use the Elastic 'New Terms' rule type on [user.name, source.geo.country_iso_code, okta.device.id]."),

"BS": dict(name="Success After Brute Force", technique="T1110 → T1078", tactic="Initial Access",
  logic="10+ failures from one external IP followed by a successful login for the same account within 30 minutes.",
  tuning="v1 grouped by account only and fired when users fixed their own expired passwords. Requiring the same external IP removed that.",
  sigma="""title: Successful Login After Failures
correlation:
  type: temporal_ordered
  rules: [6f1e2a40-ita-bf, successful-signin]
  group-by: [UserPrincipalName, IPAddress]
  timespan: 30m
tags: [attack.initial-access, attack.t1078]
level: critical""",
  kql="""SigninLogs
| where not(ipv4_is_in_any_range(IPAddress, dynamic(["198.51.100.0/24"])))
| summarize Fails = countif(ResultType == 50126), Success = countif(ResultType == 0),
            FirstOk = minif(TimeGenerated, ResultType == 0), LastFail = maxif(TimeGenerated, ResultType == 50126)
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 30m)
| where Fails >= 10 and Success > 0 and FirstOk > LastFail""",
  esql="""FROM logs-okta.system-* METADATA _id
| WHERE event.action == "user.session.start"
| STATS fails = COUNT(event.outcome == "failure" OR NULL), oks = COUNT(event.outcome == "success" OR NULL)
    BY user.name, source.ip, bucket = DATE_TRUNC(30 minutes, @timestamp)
| WHERE fails >= 10 AND oks > 0"""),

"MR": dict(name="Risky MFA Registration", technique="T1098.005", tactic="Persistence",
  logic="A new MFA method is registered from a hosting-provider or Tor IP.",
  tuning="v1 flagged any registration outside the office, which caught employees setting up new phones at home.",
  sigma="""title: MFA Method Registered From Hosting or Tor IP
logsource: {product: azure, service: auditlogs}
detection:
  selection: {OperationName: User registered security info}
  condition: selection
tags: [attack.persistence, attack.t1098.005]
level: high
# enrich InitiatedBy.user.ipAddress with ASN type in the SIEM""",
  kql="""AuditLogs
| where OperationName == "User registered security info"
| extend IP = tostring(InitiatedBy.user.ipAddress)
| join kind=inner (ThreatIntelligenceIndicator | where Tags has_any ("hosting","tor") | project IP = NetworkIP) on IP""",
  esql="""FROM logs-okta.system-*
| WHERE event.action == "user.mfa.factor.activate"
    AND (source.as.organization.name RLIKE ".*(Hosting|Cloud|VPS).*" OR okta.security_context.is_proxy == true)"""),
}
