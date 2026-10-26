"""Run detections (v1 naive and v2 tuned), score them against ground truth,
correlate alerts into incidents, and write results + SIEM rule files."""
import json
from collections import Counter
from datetime import timedelta
from pathlib import Path
import pandas as pd
from detect import run_all, correlate, SEV_POINTS, CORP
from rules import RULES

ROOT = Path(__file__).resolve().parent.parent
df = pd.read_csv(ROOT / "data/signin_logs.csv", parse_dates=["ts"], keep_default_na=False)
directory = pd.read_csv(ROOT / "data/directory.csv", keep_default_na=False)
label = dict(zip(df.event_id, df.scenario))
ev = df.set_index("event_id")

def scen_of(a):
    labs = [label[e] for e in a["event_ids"] if label[e]]
    return Counter(labs).most_common(1)[0][0] if labs else ""

def evaluate(alerts):
    stats = {}
    for rid in RULES:
        rs = [a for a in alerts if a["rule_id"] == rid]
        tp = sum(1 for a in rs if scen_of(a))
        stats[rid] = dict(alerts=len(rs), tp=tp, fp=len(rs) - tp,
                          precision=round(tp / len(rs), 3) if rs else None)
    detected = sorted({scen_of(a) for a in alerts if scen_of(a)})
    tp = sum(1 for a in alerts if scen_of(a))
    return stats, detected, dict(alerts=len(alerts), tp=tp, fp=len(alerts) - tp,
                                 precision=round(tp / len(alerts), 3) if alerts else 0)

v1 = run_all(df, directory, tuned=False)
v2 = run_all(df, directory, tuned=True)
s1, d1, t1 = evaluate(v1)
s2, d2, t2 = evaluate(v2)
scenarios = sorted(s for s in df.scenario.unique() if s)

print(f"v1: {t1['alerts']} alerts, {t1['fp']} FP, precision {t1['precision']:.1%}, scenarios {len(d1)}/{len(scenarios)}")
print(f"v2: {t2['alerts']} alerts, {t2['fp']} FP, precision {t2['precision']:.1%}, scenarios {len(d2)}/{len(scenarios)}")
for rid in RULES:
    print(f"  {rid:4} v1 {s1[rid]}  ->  v2 {s2[rid]}")

# ------------------------------------------------------------- incidents
incidents = correlate(v2, df, directory)

def title(rules, users):
    r = set(rules)
    extra = " + MFA persistence" if "MR" in r else ""
    if "MF" in r: return "MFA fatigue takeover of " + ", ".join(users)
    if "LA" in r and "PS" in r: return "Legacy IMAP spray bypassing MFA"
    if "PSS" in r: return "Low-and-slow password spray, account compromised" + extra
    if "BS" in r: return "Brute-force takeover of " + ", ".join(users)
    if "DA" in r: return "Terminated contractor account reused"
    if "IT" in r and "NC" in r: return "Session hijack of admin " + ", ".join(users)
    if "PS" in r: return "Password spray campaign"
    return RULES[rules[0]]["name"]

PLAY = {
    "BF": "Block the source IP at the IdP and firewall.",
    "BS": "Reset the password, revoke all sessions and refresh tokens.",
    "PS": "Block the spraying /24 and add it to the IdP network blocklist.",
    "PSS": "Reset the compromised account, revoke sessions, review mailbox rules and OAuth grants.",
    "MF": "Revoke sessions, reset password, switch push MFA to number matching.",
    "MR": "Remove the attacker-registered MFA method; require re-enrollment in person or by video.",
    "IT": "Revoke refresh tokens; enable token protection (device-bound sessions) for admins.",
    "NC": "Confirm with the user out-of-band before restoring access.",
    "LA": "Disable legacy authentication tenant-wide with Conditional Access.",
    "DA": "Disable the account, then audit offboarding: IdP deprovisioning failed.",
}

def tl_rows(inc):
    users = set(inc["users"])
    ext_ips = {ev.loc[e].src_ip for a in inc["alerts"] for e in a["event_ids"] if ev.loc[e].asn_type not in CORP}
    lo, hi = inc["first"] - timedelta(hours=3), inc["last"] + timedelta(hours=2)
    w = df[(df.ts >= lo) & (df.ts <= hi) & (df.user.isin(users) | df.src_ip.isin(ext_ips))].sort_values("ts")
    rows = [dict(kind="event", ts=str(r.ts), user=r.user, ip=r.src_ip, city=r.city, asn=r.asn_type, app=r.app,
                 client=r.client, result=r.result, reason=r.reason, mfa=r.mfa, device=r.device_id, attack=bool(r.scenario))
            for r in w.itertuples()]
    fails = [i for i, r in enumerate(rows) if r["result"] == "FAILURE"]
    if len(rows) > 24 and len(fails) > 12:
        drop = set(fails[6:-4])
        kept, marker_done = [], False
        for i, r in enumerate(rows):
            if i in drop:
                if not marker_done:
                    kept.append(dict(kind="gap", ts=r["ts"], count=len(drop)))
                    marker_done = True
                continue
            kept.append(r)
        rows = kept
    for a in inc["alerts"]:
        rows.append(dict(kind="alert", ts=str(a["ts"]), rule=a["rule_id"], severity=a["severity"], detail=a["detail"]))
    rows.sort(key=lambda r: (r["ts"], 0 if r["kind"] != "alert" else 1))
    return rows

inc_out = []
for inc in incidents:
    rids = [a["rule_id"] for a in inc["alerts"]]
    scen = Counter(scen_of(a) for a in inc["alerts"]).most_common(1)[0][0]
    rec = dict(id=inc["id"], title=title(rids, inc["users"]), severity=inc["severity"], score=inc["score"],
               privileged=inc["privileged"], users=inc["users"], first=str(inc["first"]), last=str(inc["last"]),
               rules=list(dict.fromkeys(rids)), true_positive=bool(scen), scenario=scen,
               ips=sorted({a["src_ip"] for a in inc["alerts"]}),
               playbook=[PLAY[r] for r in dict.fromkeys(rids) if r in PLAY], timeline=tl_rows(inc))
    if scen:
        s = df[df.scenario == scen]
        first_ev = s.ts.min()
        first_ok = s[s.result == "SUCCESS"].ts.min()
        rec["ttd_min"] = round((inc["first"] - first_ev).total_seconds() / 60, 1)
        rec["before_compromise"] = bool(inc["first"] < first_ok)
        rec["compromised"] = sorted(s[s.result == "SUCCESS"].user.unique())
    inc_out.append(rec)
    print(rec["id"], rec["severity"], rec["score"], rec["title"], rec.get("ttd_min"), rec.get("before_compromise"))

# ------------------------------------------------------------- risk + activity
priv = set(directory[directory.privileged.astype(str) == "True"].user)
risk = Counter()
for a in v2:
    if "accounts" not in a["user"]:
        risk[a["user"]] += SEV_POINTS[a["severity"]]
dirx = directory.set_index("user")
risk_out = [dict(user=u, score=min(100, round(p * (1.5 if u in priv else 1))),
                 title=dirx.at[u, "title"], dept=dirx.at[u, "dept"], privileged=u in priv)
            for u, p in risk.items()]
risk_out.sort(key=lambda r: -r["score"])

et = df.ts - timedelta(hours=4)
days = pd.date_range(df.ts.min().normalize(), df.ts.max().normalize())
daily = dict(labels=[d.strftime("%m/%d") for d in days],
             success=[int(((df.ts.dt.normalize() == d) & (df.result == "SUCCESS")).sum()) for d in days],
             failure=[int(((df.ts.dt.normalize() == d) & (df.result == "FAILURE") & (df.scenario == "")).sum()) for d in days],
             attack=[int(((df.ts.dt.normalize() == d) & (df.scenario != "")).sum()) for d in days])
fails = df[df.result == "FAILURE"]
fet = fails.ts - timedelta(hours=4)
heat = [[int(((fet.dt.weekday == wd) & (fet.dt.hour == h)).sum()) for h in range(24)] for wd in range(7)]
sources = df.groupby("asn_type").agg(events=("event_id", "count"), fail_rate=("result", lambda s: round((s == "FAILURE").mean(), 3))).reset_index()

summary = dict(
    events=len(df), accounts=int(df.user.nunique()), days=len(days),
    attack_events=int((df.scenario != "").sum()), scenarios=len(scenarios),
    v1=dict(total=t1, rules=s1, detected=len(d1)), v2=dict(total=t2, rules=s2, detected=len(d2)),
    incidents=inc_out, risk=risk_out[:8], daily=daily, heat=heat,
    sources=sources.to_dict("records"),
    rules={k: {kk: vv for kk, vv in v.items()} for k, v in RULES.items()},
)
(ROOT / "results").mkdir(exist_ok=True)
json.dump(summary, open(ROOT / "results/results.json", "w"), indent=1, default=str)
pd.DataFrame(v2).assign(event_ids=lambda d: d.event_ids.map(" ".join)).to_csv(ROOT / "results/alerts_v2.csv", index=False)

# ------------------------------------------------------------- rule exports
for sub in ["sigma", "kql", "esql"]:
    (ROOT / "rules" / sub).mkdir(parents=True, exist_ok=True)
for rid, r in RULES.items():
    slug = r["name"].lower().replace(" / ", "-").replace(" + ", "-").replace(" ", "-")
    (ROOT / f"rules/sigma/{slug}.yml").write_text(r["sigma"] + "\n")
    (ROOT / f"rules/kql/{slug}.kql").write_text(f"// {r['name']} ({r['technique']})\n// {r['logic']}\n" + r["kql"] + "\n")
    (ROOT / f"rules/esql/{slug}.esql").write_text(f"// {r['name']} ({r['technique']})\n" + r["esql"] + "\n")
print("written results/ and rules/")
