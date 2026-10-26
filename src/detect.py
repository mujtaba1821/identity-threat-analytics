"""Nine identity-threat detections, each with a naive (v1) and a tuned (v2) version.

Every alert carries the event IDs it is based on, so it can be scored against ground truth.
"""
import math
from datetime import timedelta
import pandas as pd

CORP = {"corporate", "corporate-vpn"}
RISKY_ASN = {"hosting", "tor"}
SEV_POINTS = {"Critical": 40, "High": 25, "Medium": 10}

def _alert(rid, sev, ts, user, ip, detail, ids):
    return dict(rule_id=rid, severity=sev, ts=pd.Timestamp(ts), user=user, src_ip=ip, detail=detail, event_ids=list(ids))

def km(a, b):
    p1, p2 = math.radians(a.lat), math.radians(b.lat)
    dl, dn = p2 - p1, math.radians(b.lon - a.lon)
    h = math.sin(dl / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dn / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))

def subnet(ip):
    return ip.rsplit(".", 1)[0] + ".0/24"

# ---------------------------------------------------------------- rules
def brute_force(df, tuned):
    """ATT&CK T1110.001. Many wrong passwords for one account from one source."""
    out = []
    f = df[df.reason == "bad_password"]
    for (u, ip), g in f.groupby(["user", "src_ip"]):
        corp = g.asn_type.iloc[0] in CORP
        thr = 25 if (tuned and corp) else 10
        g = g.sort_values("ts")
        c = g.set_index("ts")["event_id"].rolling("10min").count()
        hit = c[c >= thr]
        if len(hit):
            t = hit.index[0]
            ids = g[(g.ts > t - timedelta(minutes=10)) & (g.ts <= t)].event_id
            out.append(_alert("BF", "High", t, u, ip, f"{int(c.max())} wrong passwords in 10 min", ids))
    return out

def password_spray(df, tuned):
    """ATT&CK T1110.003. One source tries a few passwords across many accounts."""
    out = []
    f = df[df.reason == "bad_password"].copy()
    if tuned:
        f = f[~f.asn_type.isin(CORP)]
        f["key"] = f.src_ip.map(subnet)
        win, thr = timedelta(hours=3), 10
        ratio = df.assign(key=df.src_ip.map(subnet)).groupby("key").result.apply(lambda s: (s == "FAILURE").mean())
    else:
        f["key"] = f.src_ip
        win, thr = timedelta(hours=1), 10
    for key, g in f.groupby("key"):
        if tuned and ratio.get(key, 0) < 0.8:
            continue
        g = g.sort_values("ts").reset_index(drop=True)
        for i in range(len(g)):
            w = g[(g.ts >= g.ts[i] - win) & (g.ts <= g.ts[i])]
            if w.user.nunique() >= thr:
                allf = g[(g.ts >= g.ts[i] - win)]
                n = allf.user.nunique()
                out.append(_alert("PS", "High", g.ts[i], f"{n} accounts", key,
                                  f"{n} accounts targeted from {g.src_ip.nunique()} IP(s)", allf.event_id))
                # escalate: any success from the spraying source = compromised account
                src = df[(df.src_ip.isin(g.src_ip.unique())) & (df.result == "SUCCESS") &
                         (df.ts >= g.ts[0]) & (df.ts <= g.ts.iloc[-1] + timedelta(hours=6))]
                for u, s in src.groupby("user"):
                    s = s.sort_values("ts")
                    out.append(_alert("PSS", "Critical", s.ts.iloc[0], u, s.src_ip.iloc[0],
                                      "Login succeeded from spraying source", s.event_id))
                break
    return out

def impossible_travel(df, tuned):
    """ATT&CK T1078.004. Two successful sign-ins too far apart to be the same person."""
    out = []
    ok = df[df.result == "SUCCESS"].sort_values("ts")
    for u, g in ok.groupby("user"):
        prev = None
        for r in g.itertuples():
            if prev is not None and r.city != prev.city:
                skip = tuned and (r.asn_type in ("corporate-vpn", "mobile") or prev.asn_type in ("corporate-vpn", "mobile"))
                hrs = max((r.ts - prev.ts).total_seconds() / 3600, 1 / 60)
                spd = km(prev, r) / hrs
                if spd > 900 and not skip:
                    out.append(_alert("IT", "Medium", r.ts, u, r.src_ip,
                                      f"{prev.city} to {r.city} in {hrs*60:.0f} min ({spd:,.0f} km/h)", [prev.event_id, r.event_id]))
            prev = r
    return out

def mfa_fatigue(df, tuned):
    """ATT&CK T1621. Push-bombing until the user approves."""
    out = []
    m = df[df.mfa.isin(["push_denied", "push_approved"])]
    for u, g in m.groupby("user"):
        den = g[g.mfa == "push_denied"]
        for r in g[g.mfa == "push_approved"].itertuples():
            w = den[(den.ts >= r.ts - timedelta(minutes=20)) & (den.ts < r.ts)]
            if len(w) >= 5:
                out.append(_alert("MF", "Critical", r.ts, u, r.src_ip, f"Approved after {len(w)} denied pushes",
                                  list(w.event_id) + [r.event_id]))
    return out

def legacy_auth(df, tuned):
    """ATT&CK T1078.004. Legacy protocols (IMAP/POP/SMTP basic auth) skip MFA."""
    out = []
    l = df[df.client.str.contains("legacy") & (df.result == "SUCCESS")]
    if tuned:
        l = l[~l.asn_type.isin(CORP)]
    for (u, ip, day), g in l.groupby(["user", "src_ip", l.ts.dt.date]):
        out.append(_alert("LA", "High", g.ts.min(), u, ip, f"{len(g)} legacy-protocol logins ({g.client.iloc[0]})", g.event_id))
    return out

def dormant_account(df, tuned, directory):
    """ATT&CK T1078.004. Activity on an account that should be quiet or disabled."""
    out = []
    ok = df[df.result == "SUCCESS"].sort_values("ts")
    status = directory.set_index("user")
    for u, g in ok.groupby("user"):
        ts = g.ts.tolist()
        ids = g.event_id.tolist()
        term = status.at[u, "status"] == "terminated" if u in status.index else False
        end = pd.Timestamp(status.at[u, "end"]) if term else None
        flagged = False
        for i in range(1, len(ts)):
            gap = (ts[i] - ts[i - 1]).days
            if tuned:
                if term and ts[i] > end and not flagged:
                    out.append(_alert("DA", "Critical", ts[i], u, g.src_ip.iloc[i], f"Sign-in to account terminated {end.date()}", ids[i:i + 3]))
                    flagged = True
                elif gap > 30:
                    out.append(_alert("DA", "Medium", ts[i], u, g.src_ip.iloc[i], f"First sign-in after {gap} days", [ids[i]]))
            elif gap > 14:
                out.append(_alert("DA", "Medium", ts[i], u, g.src_ip.iloc[i], f"First sign-in after {gap} days", [ids[i]]))
    return out

def new_country(df, tuned):
    """ATT&CK T1078. Sign-in from a country never seen for this user (v2: plus a never-seen device)."""
    out = []
    ok = df[df.result == "SUCCESS"].sort_values("ts")
    learn_until = df.ts.min() + timedelta(days=3)
    for u, g in ok.groupby("user"):
        seen_c, seen_d = set(), set()
        for r in g.itertuples():
            nc, nd = r.country not in seen_c, r.device_id not in seen_d
            has_baseline = bool(seen_c) or not tuned      # v2: brand-new accounts have no history to compare
            if r.ts > learn_until and nc and has_baseline and (nd or not tuned):
                sev = "High" if tuned else "Medium"
                out.append(_alert("NC", sev, r.ts, u, r.src_ip,
                                  f"New country {r.country}" + (" on unseen device" if nd else ""), [r.event_id]))
            seen_c.add(r.country); seen_d.add(r.device_id)
    return out

def burst_then_success(df, tuned):
    """ATT&CK T1110 -> T1078. Failure burst followed by a successful login (likely compromise)."""
    out = []
    for key, g in df.groupby(["user", "src_ip"] if tuned else ["user"]):
        if tuned and g.asn_type.iloc[0] in CORP:
            continue
        g = g.sort_values("ts")
        fails = g[g.reason.isin(["bad_password", "account_locked"])]
        for r in g[g.result == "SUCCESS"].itertuples():
            w = fails[(fails.ts >= r.ts - timedelta(minutes=30)) & (fails.ts < r.ts)]
            if len(w) >= (10 if tuned else 5):
                out.append(_alert("BS", "Critical", r.ts, r.user, r.src_ip, f"Login succeeded after {len(w)} failures",
                                  list(w.event_id) + [r.event_id]))
                break
    return out

def mfa_registration(df, tuned):
    """ATT&CK T1098.005. Attacker enrolls their own MFA device for persistence."""
    out = []
    reg = df[df.app == "Security Info Registration"]
    for r in reg.itertuples():
        bad = (r.asn_type in RISKY_ASN) if tuned else (r.asn_type != "corporate")
        if bad:
            out.append(_alert("MR", "High", r.ts, r.user, r.src_ip, f"MFA method registered from {r.asn_type} IP in {r.city}", [r.event_id]))
    return out

RULES = [
    ("BF", brute_force), ("PS", password_spray), ("IT", impossible_travel), ("MF", mfa_fatigue),
    ("LA", legacy_auth), ("DA", dormant_account), ("NC", new_country), ("BS", burst_then_success),
    ("MR", mfa_registration),
]

def run_all(df, directory, tuned):
    alerts = []
    for rid, fn in RULES:
        alerts += fn(df, tuned, directory) if fn is dormant_account else fn(df, tuned)
    alerts.sort(key=lambda a: a["ts"])
    return alerts

# ---------------------------------------------------------------- correlation
def correlate(alerts, df, directory, window=timedelta(hours=24)):
    """Group alerts into incidents: same account, or same external /24, within 24 h."""
    n = len(alerts)
    parent = list(range(n))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]; i = parent[i]
        return i
    ev = df.set_index("event_id")
    keys = []
    for a in alerts:
        k = set()
        if "accounts" not in a["user"]:
            k.add(("u", a["user"]))
        for eid in a["event_ids"]:
            r = ev.loc[eid]
            if r.asn_type not in CORP:
                k.add(("n", subnet(r.src_ip)))
        keys.append(k)
    for i in range(n):
        for j in range(i + 1, n):
            if abs(alerts[i]["ts"] - alerts[j]["ts"]) <= window and keys[i] & keys[j]:
                parent[find(i)] = find(j)
    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(alerts[i])
    priv = set(directory[directory.privileged.astype(str) == "True"].user)
    incidents = []
    for g in groups.values():
        users = sorted({a["user"] for a in g if "accounts" not in a["user"]})
        score = sum(SEV_POINTS[a["severity"]] for a in g)
        if set(users) & priv:
            score *= 1.5
        sev = max((a["severity"] for a in g), key=lambda s: SEV_POINTS[s])
        incidents.append(dict(alerts=sorted(g, key=lambda a: a["ts"]), users=users,
                              first=min(a["ts"] for a in g), last=max(a["ts"] for a in g),
                              severity=sev, score=min(100, round(score)), privileged=bool(set(users) & priv)))
    incidents.sort(key=lambda x: x["first"])
    for i, inc in enumerate(incidents, 1):
        inc["id"] = f"INC-{i:03d}"
    return incidents
