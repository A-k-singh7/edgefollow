"""Writes figure2_resource_tree.svg (EdgeFollow article). Names as in the lab code; composite of the lab's runs."""
import html, sys
OUT = sys.argv[1]
COL = {"<CSEBase>": "#1d1d1d", "<AE>": "#1d1d1d", "<cnt>": "#2e7d32", "<ts>": "#6a1b9a", "<pch>": "#00838f",
       "<sub>": "#c25a00", "<acp>": "#b71c1c", "<fcnt>": "#1f5fa8", "<csr>": "#555555", "<AEAnnc>": "#555555"}
P1 = ("MN-CSE A (cse-mn-a): the devices", [
    ("", "<CSEBase>", "cse-mn-a", ""),
    ("├─ ", "<AE>", "phone", "phone-A, the vehicle"),
    ("│  ├─ ", "<cnt>", "imu", "motion"),
    ("│  ├─ ", "<cnt>", "env", "environment"),
    ("│  ├─ ", "<cnt>", "loc", "position"),
    ("│  ├─ ", "<cnt>", "radio", "cell and signal"),
    ("│  │  └─ ", "<sub>", "(an app's)", "notifies that app"),
    ("│  ├─ ", "<cnt>", "wlan", "Wi-Fi"),
    ("│  ├─ ", "<cnt>", "cmd", "commands to the phone"),
    ("│  │  └─ ", "<sub>", "cmdSub", "to the polling channel"),
    ("│  ├─ ", "<cnt>", "ack", "answers of the phone"),
    ("│  ├─ ", "<ts>", "radioTs", "numbered radio samples"),
    ("│  └─ ", "<pch>", "pch", "the phone fetches commands"),
    ("├─ ", "<acp>", "phoneReadAcp", "owner: all; reader: read"),
    ("├─ ", "<AE>", "rsu", "phone-B, the roadside sensor"),
    ("│  └─ ", "<cnt>", "imu, env, ...", "as phone-A"),
    ("└─ ", "<AE>", "mecPolicy", "the edge's own rules"),
    ("   ├─ ", "<cnt>", "constraint", "which targets it admits"),
    ("   └─ ", "<cnt>", "violations", ""),
])
P2 = ("IN-CSE (cse-in): the cloud", [
    ("", "<CSEBase>", "cse-in", ""),
    ("├─ ", "<csr>", "id-mn-a", "edge A, over Mcc"),
    ("│  └─ ", "<AEAnnc>", "phone", "the route to edge A"),
    ("├─ ", "<csr>", "id-mn-b", "edge B, over Mcc"),
    ("├─ ", "<AE>", "hoPolicy", "the handover rule"),
    ("│  ├─ ", "<cnt>", "rule", "latest instance in force"),
    ("│  └─ ", "<cnt>", "events", "one per event"),
    ("└─ ", "<AE>", "flOrch", "learning orchestrator"),
    ("   ├─ ", "<cnt>", "tasks", "a sub per selected client"),
    ("   ├─ ", "<cnt>", "ops", ""),
    ("   └─ ", "<cnt>", "model, deploy", ""),
])
P3 = ("MN-CSE A: other applications", [
    ("", "<CSEBase>", "cse-mn-a", ""),
    ("├─ ", "<AE>", "flNat", "a learning device (simulated)"),
    ("│  ├─ ", "<fcnt>", "flCap", "SDT dmCapability"),
    ("│  └─ ", "<fcnt>", "flCompute", "SDT dmAgent"),
    ("├─ ", "<AE>", "flAgg", "learning aggregator"),
    ("│  ├─ ", "<cnt>", "updates", "clients create; flAgg reads"),
    ("│  └─ ", "<cnt>", "models, rounds", ""),
    ("└─ ", "<AE>", "mec-ipe", "location proxy"),
    ("   ├─ ", "<acp>", "operator", "create only"),
    ("   ├─ ", "<acp>", "requesters", "create only"),
    ("   ├─ ", "<cnt>", "ue-registry", "operator writes"),
    ("   ├─ ", "<cnt>", "location", "operator requests"),
    ("   └─ ", "<cnt>", "location-requests", "device requests"),
])
W, H = 1440, 690
LH, TOP = 23, 112
panels = [(28, 456, P1), (504, 428, P2), (952, 460, P3)]
ROWS = max(len(p[1]) for _, _, p in panels)
o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" xml:space="preserve">',
     f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
     '<text x="28" y="40" font-family="DejaVu Sans, sans-serif" font-size="22" font-weight="bold" fill="#1d1d1d">'
     'EdgeFollow: the oneM2M resource tree, before the move</text>']
e = html.escape
for x, w, (title, rows) in panels:
    h = 70 + LH * ROWS
    o.append(f'<rect x="{x}" y="60" width="{w}" height="{h}" rx="12" fill="#f7f8fa" stroke="#9aa5b1" stroke-width="1.4"/>')
    o.append(f'<text x="{x+16}" y="86" font-family="DejaVu Sans, sans-serif" font-size="15" font-weight="bold" fill="#33475b">{e(title)}</text>')
    for i, (pre, tag, name, note) in enumerate(rows):
        y = TOP + i * LH
        s = (f'<text x="{x+16}" y="{y}" font-family="DejaVu Sans Mono, monospace" font-size="13.5">'
             f'<tspan fill="#9aa5b1">{e(pre).replace(" ", "\u00a0")}</tspan>'
             f'<tspan fill="{COL[tag]}" font-weight="bold">{e(tag)}</tspan>'
             f'<tspan fill="#1d1d1d" font-weight="bold">\u00a0{e(name)}</tspan></text>')
        o.append(s)
        if note:
            o.append(f'<text x="{x+w-14}" y="{y}" text-anchor="end" font-family="DejaVu Sans, sans-serif" font-size="12.5" fill="#666">{e(note)}</text>')
# legend
ly = 616
items = [("<cnt>", "container"), ("<ts>", "timeSeries"), ("<pch>", "pollingChannel"), ("<sub>", "subscription"),
         ("<acp>", "access control policy"), ("<fcnt>", "flexContainer"), ("<csr>", "remoteCSE"), ("<AEAnnc>", "announced AE")]
lx = 28
for tag, word in items:
    o.append(f'<text x="{lx}" y="{ly}" font-family="DejaVu Sans Mono, monospace" font-size="13" font-weight="bold" fill="{COL[tag]}">{e(tag)}</text>')
    tw = 8.2 * len(tag)
    o.append(f'<text x="{lx+tw+6}" y="{ly}" font-family="DejaVu Sans, sans-serif" font-size="13" fill="#444">{e(word)}</text>')
    lx += tw + 6 + 7.4 * len(word) + 26
o.append('<text x="28" y="650" font-family="DejaVu Sans, sans-serif" font-size="13" fill="#555">Names as in the lab code; a composite of the lab\'s runs. The phone\'s containers keep at most 2000 instances (mni). In the</text>')
o.append('<text x="28" y="669" font-family="DejaVu Sans, sans-serif" font-size="13" fill="#555">move, the AE "phone" goes to MN-CSE B with all its child resources, and its announced copy goes under id-mn-b at the IN-CSE.</text>')
o.append('</svg>')
open(OUT, "w").write("\n".join(o) + "\n")
print("rows:", [len(p[2][1]) for p in panels])
