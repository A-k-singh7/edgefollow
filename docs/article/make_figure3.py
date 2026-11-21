"""Figure 3: the handover as the runs with the real phones did it (phone/estimed_poc2.py, sitting B, runs 1-3).

Run: python3 -I -B make_figure3.py  ->  figure3_handover_sequence.svg (render to PNG with headless Chrome).
"""
from pathlib import Path
from xml.sax.saxutils import escape

W, H = 1320, 1080
COLS = {"phone": 80, "mnA": 250, "m12": 430, "orch": 640, "in": 850, "m40": 1010, "mnB": 1160}
HEAD = {"phone": ("phone-A", "vehicle app"), "mnA": ("MN-CSE A", "edge A"), "m12": ("MEC 012", "radio info"),
        "orch": ("Orchestrator", "an AE, on the PC"), "in": ("IN-CSE", "context hub, records"),
        "m40": ("MEC 040", "federation"), "mnB": ("MN-CSE B", "edge B")}
STYLE = {"m2m": ("#3a3a3a", "", "ah"), "mec": ("#1f5fa8", "", "ahB"), "usb": ("#7a7a7a", "7 5", "ahG"),
         "ret": ("#1f5fa8", "5 4", "ahB")}
# (from, to, style, label lines)
MSGS = [
    ("phone", "mnA", "m2m", ["numbered samples, every 5 s"]),
    ("m12", "orch", "mec", ["radio report:", "RSRP below threshold"]),
    ("orch", "in", "m2m", ["TRIGGERED; hub recommends;", "acceptance record (a rule)"]),
    ("orch", "m40", "mec", ["list peers, select one for edge A"]),
    ("m40", "orch", "ret", ["edge B"]),
    ("orch", "in", "m2m", ["open the handover transaction"]),
    ("orch", "phone", "usb", ["pause the stream"]),
    ("orch", "mnB", "m2m", ["AE + 5 containers; every sample copied, bit-identical"]),
    ("orch", "mnB", "m2m", ["ACPs (reader yes, stranger no), subscription S1"]),
    ("orch", "phone", "usb", ["restart the app's service, pointed at edge B"]),
    ("phone", "mnB", "m2m", ["new samples; S1 notifies its subscriber"]),
    ("orch", "in", "m2m", ["serving edge: B"]),
    ("orch", "mnA", "m2m", ["release the AE (edge A then answers 404)"]),
    ("orch", "in", "m2m", ["COMPLETED; transaction closed"]),
    ("orch", "mnB", "m2m", ["after the move: a command for the vehicle (ping)"]),
    ("phone", "mnB", "m2m", ["poll (pollingChannel), take the command, acknowledge"]),
]
COMPLETED = 13          # index of the COMPLETED row in MSGS: the end of the trigger-to-completed bracket
HALO = 'paint-order="stroke" stroke="#ffffff" stroke-width="5" stroke-linejoin="round"'


def svg() -> str:
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
         'font-family="DejaVu Sans, Noto Sans, Liberation Sans, sans-serif">', "  <defs>"]
    for mid, col in (("ah", "#3a3a3a"), ("ahB", "#1f5fa8"), ("ahG", "#7a7a7a")):
        o.append(f'    <marker id="{mid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                 f'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{col}"/></marker>')
    o += ["  </defs>", f'  <rect x="0" y="0" width="{W}" height="{H}" fill="#ffffff"/>',
          '  <text x="24" y="38" font-size="22" font-weight="bold" fill="#1d1d1d">EdgeFollow: the move, as the '
          'runs with the real phones did it</text>']
    top, life_end = 62, 0
    ys, y = [], 172
    for m in MSGS:
        y += 16 * (len(m[3]) - 1)
        ys.append(y)
        y += 48
    life_end = ys[-1] + 34
    assert MSGS[COMPLETED][3][0].startswith("COMPLETED")
    for k, x in COLS.items():
        a, b = HEAD[k]
        fill, stroke = ("#eaf1fb", "#1f5fa8") if k in ("m12", "m40") else ("#ffffff", "#3a3a3a")
        o.append(f'  <line x1="{x}" y1="{top + 58}" x2="{x}" y2="{life_end}" stroke="#b5b5b5" stroke-width="1.5" '
                 'stroke-dasharray="4 4"/>')
        o.append(f'  <rect x="{x - 72}" y="{top}" width="144" height="58" rx="8" fill="{fill}" stroke="{stroke}" '
                 'stroke-width="1.5"/>')
        o.append(f'  <text x="{x}" y="{top + 24}" font-size="15" font-weight="bold" text-anchor="middle" '
                 f'fill="#1d1d1d">{escape(a)}</text>')
        o.append(f'  <text x="{x}" y="{top + 44}" font-size="12" text-anchor="middle" fill="#444">{escape(b)}</text>')
    for (f, t, st, lines), y in zip(MSGS, ys):
        col, dash, mk = STYLE[st]
        x1, x2 = COLS[f], COLS[t]
        d = 1 if x2 > x1 else -1
        da = f' stroke-dasharray="{dash}"' if dash else ""
        o.append(f'  <line x1="{x1 + 3 * d}" y1="{y}" x2="{x2 - 4 * d}" y2="{y}" stroke="{col}" stroke-width="2"'
                 f'{da} marker-end="url(#{mk})"/>')
        cx = (x1 + x2) / 2
        for i, ln in enumerate(reversed(lines)):
            o.append(f'  <text x="{cx:.0f}" y="{y - 7 - 16 * i}" font-size="13" text-anchor="middle" '
                     f'fill="{"#123d6e" if st in ("mec", "ret") else ("#555" if st == "usb" else "#1d1d1d")}" '
                     f'{HALO}>{escape(ln)}</text>')
    # brackets: trigger -> completed, and the time without samples
    for x, y1, y2, text in ((1262, ys[1], ys[COMPLETED], "trigger to completed: 16.5 to 16.6 s"),
                            (1292, ys[6], ys[10], "no samples: about 8.7 s")):
        o.append(f'  <path d="M{x - 8},{y1} H{x} V{y2} H{x - 8}" fill="none" stroke="#c25a00" stroke-width="2"/>')
        o.append(f'  <text x="{x + 15}" y="{(y1 + y2) / 2:.0f}" font-size="13" font-weight="bold" fill="#c25a00" '
                 f'text-anchor="middle" transform="rotate(-90 {x + 15} {(y1 + y2) / 2:.0f})">{escape(text)}</text>')
    ly = life_end + 40
    for i, (st, label) in enumerate((("m2m", "oneM2M request (HTTP)"), ("mec", "ETSI MEC API (HTTP)"),
                                     ("usb", "USB command from the PC to the phone app (lab only)"))):
        col, dash, mk = STYLE[st]
        x0 = 40 + i * 300
        da = f' stroke-dasharray="{dash}"' if dash else ""
        o.append(f'  <line x1="{x0}" y1="{ly}" x2="{x0 + 50}" y2="{ly}" stroke="{col}" stroke-width="2"{da} '
                 f'marker-end="url(#{mk})"/>')
        o.append(f'  <text x="{x0 + 62}" y="{ly + 5}" font-size="13" fill="#333">{escape(label)}</text>')
    o.append(f'  <text x="24" y="{ly + 40}" font-size="13" fill="#555">Times: runs 1 to 3 at a 5 s period. '
             'The orchestrator writes the acceptance record by a rule; in the simulated tests, it also checks MEC 011 '
             'and uses an</text>')
    o.append(f'  <text x="24" y="{ly + 58}" font-size="13" fill="#555">announced AE as the route. '
             'Records: poc2_run1.json to poc2_run3.json.</text>')
    o.append("</svg>")
    assert ly + 70 <= H, ly
    return "\n".join(o) + "\n"


if __name__ == "__main__":
    out = Path(__file__).with_name("figure3_handover_sequence.svg")
    out.write_text(svg())
    print(out)
