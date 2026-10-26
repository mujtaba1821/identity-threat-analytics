"""Generate 30 days of synthetic identity-provider sign-in logs (Okta / Entra ID style).

Benign traffic deliberately includes the things that cause false positives in real SOCs:
business travel, a global VPN with a Frankfurt exit node, mobile carrier IPs that geolocate
to a hub city, password-expiry lockouts, a service account using legacy SMTP auth, and an
employee returning from leave. Six attack scenarios are injected and labeled as ground truth.

All IP addresses come from reserved ranges (RFC 5737 documentation, RFC 2544
benchmarking for attacker infrastructure, RFC 6598 CGNAT for mobile carriers),
so no real host is implicated.
"""
import random
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd

random.seed(7)
START = datetime(2026, 9, 26)          # UTC
DAYS = 30
OUT = Path(__file__).resolve().parent.parent / "data"

# name: (country, lat, lon, utc_offset_hours)
LOC = {
    "Teaneck, NJ": ("US", 40.89, -74.01, -4), "Philadelphia, PA": ("US", 39.95, -75.17, -4),
    "Chicago, IL": ("US", 41.88, -87.63, -5), "Austin, TX": ("US", 30.27, -97.74, -5),
    "Denver, CO": ("US", 39.74, -104.99, -6), "Raleigh, NC": ("US", 35.78, -78.64, -4),
    "Boston, MA": ("US", 42.36, -71.06, -4), "Ashburn, VA": ("US", 39.04, -77.49, -4),
    "Frankfurt, DE": ("DE", 50.11, 8.68, 2), "Dallas, TX": ("US", 32.78, -96.80, -5),
    "Atlanta, GA": ("US", 33.75, -84.39, -4), "London, GB": ("GB", 51.51, -0.13, 1),
    "Tokyo, JP": ("JP", 35.68, 139.69, 9), "Toronto, CA": ("CA", 43.65, -79.38, -4),
    "Nuremberg, DE": ("DE", 49.45, 11.08, 2), "Bucharest, RO": ("RO", 44.43, 26.10, 3),
    "Amsterdam, NL": ("NL", 52.37, 4.90, 2), "Hanoi, VN": ("VN", 21.03, 105.85, 7),
    "Sao Paulo, BR": ("BR", -23.55, -46.63, -3), "Miami, FL": ("US", 25.76, -80.19, -4),
}
OFFICE_IP = {"Teaneck, NJ": "198.51.100.10", "Philadelphia, PA": "198.51.100.20", "Chicago, IL": "198.51.100.30"}
VPN = {"Ashburn, VA": "198.51.100.200", "Frankfurt, DE": "198.51.100.201"}
REMOTE = ["Austin, TX", "Denver, CO", "Raleigh, NC", "Boston, MA"]
APPS = ["Outlook", "Teams", "SharePoint", "Salesforce", "Workday", "Jira", "Slack"]
APP_W = [30, 25, 15, 10, 5, 10, 5]

SURNAMES = """okafor nguyen reyes cohen alvarez walsh kim shah brooks martin fischer rossi tanaka
lopez murphy chen patel garcia johnson silva novak ahmed baker clarke diaz evans ford gupta hayes
ito jensen khan lee moreno nash ortiz park quinn rivera singh torres usman vargas wong young zhang
abbott bell carter dunn ellis frost grant hill irwin jacobs knight lowe mills noble owens price reed
stone tate upton vance west yates adams bishop cruz doyle edwards flynn gibson hart ingram jordan
kelly lynch mason nolan oneil perez ross shaw todd underwood vega wade xu yoon zamora ali haddad
mensah sato kowalski dubois romano bauer lindqvist oconnor varga petrov""".split()

users = []
for i, s in enumerate(SURNAMES[:119]):
    first = "dtmsrkjpalenhcgbvfw"[i % 19]
    fixed = {"okafor": "d", "nguyen": "t", "reyes": "m", "cohen": "s", "alvarez": "r",
             "walsh": "k", "kim": "j", "shah": "p", "brooks": "s", "martin": "l", "fischer": "e",
             "rossi": "n", "garcia": "c", "lopez": "e", "murphy": "a", "chen": "n", "patel": "h"}
    users.append(f"{fixed.get(s, first)}.{s}")
users = list(dict.fromkeys(users))
DEPTS = ["Finance", "Sales", "Engineering", "Operations", "HR", "Legal", "Marketing"]

directory = []
for i, u in enumerate(users):
    office = random.random() < 0.7
    home = random.choice(list(OFFICE_IP)) if office else random.choice(REMOTE)
    directory.append(dict(user=u, dept=random.choice(DEPTS), title="Analyst", privileged=False,
                          status="active", start=START.date(), end="", mfa_registered=True,
                          ca_excluded=False, home=home, office=office))
D = {d["user"]: d for d in directory}
D["d.okafor"].update(dept="Finance", title="Senior Accountant", ca_excluded=True, home="Teaneck, NJ", office=True)
D["m.reyes"].update(dept="Finance", title="Chief Financial Officer", home="Teaneck, NJ", office=True)
for u in ["s.cohen", "e.lopez", "a.murphy", "n.chen", "h.patel"]:
    if u in D:
        D[u].update(dept="IT", title="Systems Administrator", privileged=True, home="Teaneck, NJ", office=True)
D["t.nguyen"].update(dept="Sales", title="Account Executive (new hire)", start=datetime(2026, 10, 5).date(), mfa_registered=False)
D["k.walsh"].update(dept="Engineering", title="Contractor", status="terminated", end="2026-10-01", home="Boston, MA", office=False)
D["r.alvarez"].update(dept="Legal", title="Paralegal")
D["j.kim"].update(home="Teaneck, NJ", office=True)
D["p.shah"].update(home="Philadelphia, PA", office=True)
directory.append(dict(user="svc-scanner", dept="IT", title="Scan-to-email service account", privileged=False,
                      status="active", start=START.date(), end="", mfa_registered=False, ca_excluded=True,
                      home="Teaneck, NJ", office=True))
D["svc-scanner"] = directory[-1]
LEAVE = {"p.shah": (datetime(2026, 10, 1), datetime(2026, 10, 20))}
TRIPS = {  # user: (depart_day_index, return_day_index, city)
    "s.brooks": (8, 13, "London, GB"), "l.martin": (15, 19, "Tokyo, JP"),
    "e.fischer": (3, 7, "London, GB"), "n.rossi": (20, 24, "Toronto, CA"),
    "c.garcia": (11, 14, "Miami, FL"),
}
TRIPS = {u: v for u, v in TRIPS.items() if u in D}
for i, u in enumerate(TRIPS):
    D[u]["office"] = True
    D[u]["home"] = "Teaneck, NJ"

rows = []
def ev(ts, user, ip, asn, city, device, app, result, reason="", mfa="", client="Browser", scenario=""):
    c, lat, lon, _ = LOC[city]
    rows.append(dict(ts=ts, user=user, src_ip=ip, asn_type=asn, city=city, country=c, lat=lat, lon=lon,
                     device_id=device, app=app, client=client, result=result, reason=reason, mfa=mfa,
                     scenario=scenario))

def mfa_for(u, client="Browser"):
    if "legacy" in client:
        return "not_supported"
    if D[u]["ca_excluded"]:
        return "not_required"
    return "push_approved" if random.random() < 0.35 else "token"

uidx = {u: i for i, u in enumerate(D)}
def home_ip(u):
    return f"203.0.113.{uidx[u] % 250 + 1}"

def pick_source(u, weekday):
    d = D[u]
    r = random.random()
    if d["office"] and weekday:
        if r < 0.60: return OFFICE_IP[d["home"]], "corporate", d["home"], "laptop"
        if r < 0.86: return home_ip(u), "residential", d["home"], "laptop"
        if r < 0.97:
            node = "Frankfurt, DE" if random.random() < 0.08 else "Ashburn, VA"
            return VPN[node], "corporate-vpn", node, "laptop"
    else:
        if r < 0.62: return home_ip(u), "residential", d["home"], "laptop"
        if r < 0.95:
            node = "Frankfurt, DE" if random.random() < 0.08 else "Ashburn, VA"
            return VPN[node], "corporate-vpn", node, "laptop"
    hub = random.choice(["Dallas, TX", "Atlanta, GA"])
    return f"100.{64 + uidx[u] % 60}.{random.randint(0, 255)}.{random.randint(1, 254)}", "mobile", hub, "phone"

# ---------------- benign traffic ----------------
for day in range(DAYS):
    date = START + timedelta(days=day)
    weekday = date.weekday() < 5
    for u, d in D.items():
        if u == "svc-scanner":
            if weekday:
                for _ in range(random.randint(6, 14)):
                    ts = date + timedelta(hours=random.uniform(12, 22))
                    ev(ts, u, OFFICE_IP["Teaneck, NJ"], "corporate", "Teaneck, NJ", "scanner-mfp-02",
                       "Exchange Online (SMTP)", "SUCCESS", mfa="not_supported", client="SMTP (legacy)")
            continue
        if date.date() < d["start"]:
            continue
        if u == "k.walsh" and date > datetime(2026, 9, 27, 23):
            continue
        if u in LEAVE and LEAVE[u][0] <= date < LEAVE[u][1]:
            continue
        trip = TRIPS.get(u)
        city_override = None
        if trip:
            if day == trip[0] or day == trip[1]:      # travel days: no sign-ins
                continue
            if trip[0] < day < trip[1]:
                city_override = trip[2]
        n = random.randint(2, 5) if weekday else (random.randint(1, 2) if random.random() < 0.25 else 0)
        if city_override:
            n = random.randint(1, 3)
        expiry = date.date() == datetime(2026, 10, 1).date() and random.random() < 0.3
        for k in range(n):
            if city_override:
                ip, asn, city, dev = f"203.0.113.{200 + list(TRIPS).index(u)}", "residential", city_override, "laptop"
            else:
                ip, asn, city, dev = pick_source(u, weekday)
            off = LOC[d["home"] if not city_override else city_override][3]
            local_h = random.uniform(8, 18.5) if weekday else random.uniform(10, 21)
            ts = date + timedelta(hours=local_h - off)
            device = f"{u}-{dev}"
            if random.random() < 0.002:
                device = f"{u}-laptop-new"
            app = random.choices(APPS, APP_W)[0]
            if expiry and k == 0:
                for j in range(random.randint(2, 5)):
                    ev(ts - timedelta(seconds=40 * (j + 1)), u, ip, asn, city, device, app, "FAILURE", "bad_password")
            elif random.random() < 0.05:
                ev(ts - timedelta(seconds=35), u, ip, asn, city, device, app, "FAILURE", "bad_password")
            if not d["ca_excluded"] and random.random() < 0.012:
                ev(ts - timedelta(seconds=70), u, ip, asn, city, device, app, "FAILURE", "mfa_denied", "push_denied")
                ev(ts, u, ip, asn, city, device, app, "SUCCESS", mfa="push_approved")
            else:
                ev(ts, u, ip, asn, city, device, app, "SUCCESS", mfa=mfa_for(u))

# benign MFA (security info) registrations: phone upgrades, done at home or in office
for u in random.sample([u for u in D if u not in ("svc-scanner", "k.walsh", "t.nguyen")], 9):
    ts = START + timedelta(days=random.randint(4, 28), hours=random.uniform(13, 22))
    if random.random() < 0.6:
        ev(ts, u, home_ip(u), "residential", D[u]["home"], f"{u}-phone", "Security Info Registration", "SUCCESS", mfa="push_approved")
    else:
        ev(ts, u, OFFICE_IP.get(D[u]["home"], OFFICE_IP["Teaneck, NJ"]), "corporate",
           D[u]["home"] if D[u]["home"] in OFFICE_IP else "Teaneck, NJ", f"{u}-phone", "Security Info Registration", "SUCCESS", mfa="push_approved")
# t.nguyen's legitimate first day (new hire)
ev(datetime(2026, 10, 5, 13, 20), "t.nguyen", OFFICE_IP["Teaneck, NJ"] if D["t.nguyen"]["home"] == "Teaneck, NJ" else OFFICE_IP.get(D["t.nguyen"]["home"], "198.51.100.10"),
   "corporate", D["t.nguyen"]["home"] if D["t.nguyen"]["home"] in OFFICE_IP else "Teaneck, NJ", "t.nguyen-laptop", "Outlook", "SUCCESS", mfa="not_registered")

# j.kim locks himself out (forgot new password), helpdesk resets it
t = datetime(2026, 10, 13, 13, 5)
for j in range(14):
    ev(t + timedelta(seconds=25 * j), "j.kim", OFFICE_IP["Teaneck, NJ"], "corporate", "Teaneck, NJ", "j.kim-laptop", "Outlook", "FAILURE", "bad_password")
for j in range(2):
    ev(t + timedelta(seconds=360 + 30 * j), "j.kim", OFFICE_IP["Teaneck, NJ"], "corporate", "Teaneck, NJ", "j.kim-laptop", "Outlook", "FAILURE", "account_locked")
ev(t + timedelta(minutes=24), "j.kim", OFFICE_IP["Teaneck, NJ"], "corporate", "Teaneck, NJ", "j.kim-laptop", "Outlook", "SUCCESS", mfa="push_approved")

# ---------------- attack scenarios (ground truth) ----------------
active = [u for u in D if u not in ("svc-scanner", "k.walsh")]

# S1: Tor brute force on an account excluded from MFA -> takeover
t, S = datetime(2026, 10, 3, 6, 13), "S1"
for j in range(46):
    ev(t + timedelta(seconds=9 * j), "d.okafor", "198.18.44.17", "tor", "Nuremberg, DE", "unknown-linux-firefox", "Outlook", "FAILURE", "bad_password", scenario=S)
ev(t + timedelta(seconds=9 * 46 + 15), "d.okafor", "198.18.44.17", "tor", "Nuremberg, DE", "unknown-linux-firefox", "Outlook", "SUCCESS", mfa="not_required", scenario=S)
ev(t + timedelta(minutes=19), "d.okafor", "198.18.44.17", "tor", "Nuremberg, DE", "unknown-linux-firefox", "SharePoint", "SUCCESS", mfa="not_required", scenario=S)

# S2: low-and-slow password spray rotating across 4 hosting IPs; hits an un-enrolled new hire
S = "S2"
targets = random.sample([u for u in active if u != "t.nguyen"], 69) + ["t.nguyen"]
random.shuffle(targets)
t0 = datetime(2026, 10, 8, 3, 0)
for j, u in enumerate(targets):
    ts = t0 + timedelta(seconds=j * 145 + random.randint(0, 40))
    ip = f"198.18.80.{11 + j % 4}"
    if u == "t.nguyen":
        ev(ts, u, ip, "hosting", "Bucharest, RO", "python-requests", "Outlook", "SUCCESS", mfa="not_registered", scenario=S)
        ev(ts + timedelta(minutes=6), u, ip, "hosting", "Bucharest, RO", "attacker-android", "Security Info Registration", "SUCCESS", mfa="not_registered", scenario=S)
        ev(ts + timedelta(minutes=9), u, ip, "hosting", "Bucharest, RO", "attacker-android", "Salesforce", "SUCCESS", mfa="push_approved", scenario=S)
    else:
        ev(ts, u, ip, "hosting", "Bucharest, RO", "python-requests", "Outlook", "FAILURE", "bad_password", scenario=S)

# S3: MFA fatigue against the CFO with phished credentials, then payroll access
t, S = datetime(2026, 10, 14, 5, 38), "S3"
for j in range(11):
    ev(t + timedelta(seconds=78 * j), "m.reyes", "198.18.120.5", "hosting", "Amsterdam, NL", "unknown-win-edge", "Workday", "FAILURE", "mfa_denied", "push_denied", scenario=S)
ev(t + timedelta(seconds=78 * 11 + 20), "m.reyes", "198.18.120.5", "hosting", "Amsterdam, NL", "unknown-win-edge", "Workday", "SUCCESS", mfa="push_approved", scenario=S)
ev(t + timedelta(minutes=21), "m.reyes", "198.18.120.5", "hosting", "Amsterdam, NL", "unknown-win-edge", "Outlook", "SUCCESS", mfa="token", scenario=S)

# S4: session-token theft from an IT admin, replayed from overseas against cloud consoles
S = "S4"
ev(datetime(2026, 10, 17, 13, 58), "s.cohen", OFFICE_IP["Teaneck, NJ"], "corporate", "Teaneck, NJ", "s.cohen-laptop", "Azure Portal", "SUCCESS", mfa="push_approved")
ev(datetime(2026, 10, 17, 14, 29), "s.cohen", "198.18.150.9", "hosting", "Hanoi, VN", "unknown-mac-chrome", "AWS Console", "SUCCESS", mfa="token", scenario=S)
ev(datetime(2026, 10, 17, 14, 41), "s.cohen", "198.18.150.9", "hosting", "Hanoi, VN", "unknown-mac-chrome", "Azure Portal", "SUCCESS", mfa="token", scenario=S)

# S5: legacy IMAP password spray (bypasses MFA), one hit
S = "S5"
targets = random.sample([u for u in active if u not in ("r.alvarez", "t.nguyen")], 24) + ["r.alvarez"]
random.shuffle(targets)
t0 = datetime(2026, 10, 20, 8, 0)
for j, u in enumerate(targets):
    ts = t0 + timedelta(seconds=j * 95)
    ok = u == "r.alvarez"
    ev(ts, u, "198.18.200.33", "hosting", "Sao Paulo, BR", "imap-client", "Exchange Online (IMAP)", "SUCCESS" if ok else "FAILURE",
       "" if ok else "bad_password", "not_supported", "IMAP (legacy)", scenario=S)
    if ok:
        for m in range(3):
            ev(ts + timedelta(minutes=20 * (m + 1)), u, "198.18.200.33", "hosting", "Sao Paulo, BR", "imap-client",
               "Exchange Online (IMAP)", "SUCCESS", "", "not_supported", "IMAP (legacy)", scenario=S)

# S6: terminated contractor reuses still-enabled account and exports CRM data
S = "S6"
for m, app in enumerate(["Salesforce", "Salesforce", "SharePoint"]):
    ev(datetime(2026, 10, 22, 15, 12) + timedelta(minutes=14 * m), "k.walsh", "198.19.23.40", "residential", "Toronto, CA",
       "k.walsh-home-pc", app, "SUCCESS", mfa="push_approved", scenario=S)

df = pd.DataFrame(rows).sort_values("ts").reset_index(drop=True)
df.insert(0, "event_id", [f"E{i:05d}" for i in range(len(df))])
OUT.mkdir(exist_ok=True)
df.to_csv(OUT / "signin_logs.csv", index=False)
dirdf = pd.DataFrame(directory)[["user", "dept", "title", "privileged", "status", "end", "mfa_registered", "ca_excluded"]]
dirdf.to_csv(OUT / "directory.csv", index=False)
print(f"{len(df):,} events | {df.user.nunique()} accounts | attack events: {(df.scenario != '').sum()}")
