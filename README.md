# Identity Threat Analytics

Detection engineering for identity-based attacks. Nine MITRE ATT&CK-mapped detections hunt through 30 days of Okta / Entra ID-style sign-in logs, get measured against ground truth, get tuned, and then correlate into incidents a SOC analyst can act on.

**Result:** tuning cut alert volume from **783 to 19** and raised precision from **2.3% to 100%**, while still catching **all 6 attack scenarios**. Three of the six were caught *before* the attacker got in.

| | v1 (naive rules) | v2 (tuned rules) |
|---|---|---|
| Alerts | 783 | 19 |
| False positives | 765 | 0 |
| Precision | 2.3% | 100% |
| Attack scenarios detected | 6 / 6 | 6 / 6 |
| Incidents after correlation | — | 6 |

> Precision is measured on a synthetic dataset where the benign noise was designed by the author. Real environments are messier, so treat 100% as "no known false positives on this data", not a production claim.

## The dataset

`src/generate.py` builds 8,536 sign-in events for 106 employees and 1 service account. Benign traffic includes the things that cause false positives in real SOCs:

- Business trips to London, Tokyo, Toronto and Miami
- A corporate VPN with a Frankfurt exit node
- Mobile carrier IPs that geolocate to a hub city (Dallas, Atlanta), not the user
- A password-expiry day (Oct 1) with a wave of failed logins
- An employee who locks himself out and gets reset by the helpdesk
- A scan-to-email printer using legacy SMTP authentication every day
- An employee returning from 19 days of leave
- Employees registering MFA on new phones from home

Six attack scenarios are injected and labeled:

| # | Scenario | ATT&CK |
|---|---|---|
| S1 | Tor brute force against an account excluded from MFA → takeover | T1110.001, T1078 |
| S2 | Low-and-slow password spray rotated across 4 IPs → hits an un-enrolled new hire → attacker registers their own MFA | T1110.003, T1098.005 |
| S3 | MFA push-bombing of the CFO at 1:40 AM → approval → Workday access | T1621 |
| S4 | Stolen session token of an IT admin replayed from Hanoi against AWS / Azure consoles | T1078.004, T1550.004 |
| S5 | Legacy IMAP password spray that bypasses MFA | T1110.003, T1078.004 |
| S6 | Terminated contractor's still-enabled account used to export CRM data | T1078.004 |

All IPs come from reserved ranges (RFC 5737, RFC 2544, RFC 6598). No real host is implicated.

## Detections and what tuning fixed

| Rule | ATT&CK | v1 precision | v2 precision | The tuning lesson |
|---|---|---|---|---|
| Brute Force | T1110.001 | 50% | 100% | Office lockouts need a higher threshold than external IPs |
| Password Spraying | T1110.003 | 100%* | 100% | *v1 missed S2 entirely. Grouping by /24 instead of IP caught the rotating spray |
| Spray Success | T1110.003→T1078 | 100% | 100% | Escalates any successful login from a spraying source |
| Impossible Travel | T1078.004 | 0.6% | 100% | 672 false positives came from VPN exit nodes and mobile carrier geolocation |
| MFA Fatigue | T1621 | 100% | 100% | Worked out of the box |
| Legacy Auth Login | T1078.004 | 4.8% | 100% | The printer service account; restrict to external IPs |
| Terminated / Dormant | T1078.004 | 50% | 100% | Joining the HR directory beats guessing from inactivity gaps |
| New Country + Device | T1078 | 9.4% | 100% | Travelers bring their own laptop; attackers don't |
| Success After Brute Force | T1110→T1078 | 12.5% | 100% | Users fixing their own expired password looked like compromise |
| Risky MFA Registration | T1098.005 | 14.3% | 100% | Only hosting / Tor sources matter |

## Incident correlation

Alerts on the same account, or from the same external /24, within 24 hours merge into one incident. Each incident gets a 0–100 risk score (Critical 40, High 25, Medium 10; ×1.5 for privileged accounts), a timeline of the surrounding sign-ins, and a response playbook.

## SIEM-ready rules

Every detection is translated for production use in `rules/`:

- `rules/kql/` — Microsoft Sentinel (Entra ID `SigninLogs` / `AuditLogs`)
- `rules/esql/` — Elastic Security with the Okta integration
- `rules/sigma/` — Sigma v2, including correlation rules for thresholds

## Run it

```bash
pip install -r requirements.txt
python src/generate.py   # writes data/signin_logs.csv and data/directory.csv
python src/run.py        # runs v1 + v2, prints metrics, writes results/ and rules/
```

Open `dashboard/index.html` for the interactive incident dashboard.

## Repo layout

```
src/generate.py   synthetic log generator with ground-truth labels
src/detect.py     9 detections (v1 + v2), incident correlation, scoring
src/rules.py      rule catalog with KQL, ES|QL and Sigma translations
src/run.py        evaluation, incidents, exports
data/             signin_logs.csv, directory.csv
results/          results.json, alerts_v2.csv
rules/            kql/, esql/, sigma/
dashboard/        index.html
```

Built by Mujtaba Ali — Cybersecurity Analytics & Operations, Penn State.
