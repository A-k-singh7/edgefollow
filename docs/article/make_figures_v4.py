"""The six figure_*.svg of docs/article/ARTICLE.md (figure_onem2m_mec, figure_deployment_options, figure_route_checks,
figure_two_implementations, figure_sandbox_driven, figure_protocols), in the style of make_figure3.py (oneM2M dark
grey, MEC blue, lab USB dashed grey, highlights orange). Run: python3 -I -B make_figures_v4.py  ->  the six .svg;
render each to PNG with headless Chrome. Every fact drawn here is in the article text with its record; the protocol
numbers are from records/proto/proto_bench_20261121T033502Z_public.json (median / p95 over 3 repeats, loopback,
ACME 2026.5.3)."""
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parent
INK, MUTED, GRID = "#1d1d1d", "#555555", "#d9d9d9"
M2M, MEC, USB, HI, OK, BAD = "#3a3a3a", "#1f5fa8", "#7a7a7a", "#c25a00", "#2e7d32", "#b3261e"
MECFILL, HIFILL, OKFILL, BADFILL, BOXFILL = "#eaf1fb", "#fdf0e6", "#e8f3ea", "#fbeaea", "#ffffff"
FONT = 'font-family="DejaVu Sans, Noto Sans, Liberation Sans, sans-serif"'


class Svg:
    def __init__(self, w, h, title):
        self.w, self.h = w, h
        self.o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" {FONT}>',
                  "<defs>"]
        for mid, col in (("aK", M2M), ("aB", MEC), ("aG", USB), ("aO", HI), ("aR", BAD), ("aE", OK)):
            self.o.append(f'<marker id="{mid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                          f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{col}"/></marker>')
        self.o += ["</defs>", f'<rect x="0" y="0" width="{w}" height="{h}" fill="#ffffff"/>',
                   f'<text x="24" y="38" font-size="22" font-weight="bold" fill="{INK}">{escape(title)}</text>']

    def box(self, x, y, w, h, lines, stroke=M2M, fill=BOXFILL, bold_first=True, size=14, rx=8, dash=None, anchor="middle"):
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" '
                      f'stroke-width="1.6"{da}/>')
        n = len(lines)
        y0 = y + h / 2 - (n - 1) * (size + 4) / 2 + size / 3
        tx = x + w / 2 if anchor == "middle" else x + 12
        for i, ln in enumerate(lines):
            wt = ' font-weight="bold"' if (i == 0 and bold_first) else ""
            col = INK if i == 0 else MUTED
            fs = size if i == 0 else size - 2
            self.o.append(f'<text x="{tx:.0f}" y="{y0 + i * (size + 4):.0f}" font-size="{fs}"{wt} text-anchor="{anchor}" '
                          f'fill="{col}">{escape(ln)}</text>')

    def area(self, x, y, w, h, label, stroke="#bdbdbd", fill="#fafafa"):
        self.o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" stroke="{stroke}" '
                      f'stroke-width="1.2" stroke-dasharray="6 4"/>')
        self.o.append(f'<text x="{x + 12}" y="{y + 20}" font-size="13" font-weight="bold" fill="{MUTED}">{escape(label)}</text>')

    def arrow(self, x1, y1, x2, y2, col=M2M, mk="aK", label=None, dash=None, both=False, lx=None, ly=None, lcol=None,
              size=12, width=2):
        da = f' stroke-dasharray="{dash}"' if dash else ""
        start = f' marker-start="url(#{mk})"' if both else ""
        self.o.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{col}" stroke-width="{width}"{da}{start} '
                      f'marker-end="url(#{mk})"/>')
        if label:
            cx = lx if lx is not None else (x1 + x2) / 2
            cy = ly if ly is not None else (y1 + y2) / 2 - 6
            for i, ln in enumerate(label if isinstance(label, list) else [label]):
                self.o.append(f'<text x="{cx:.0f}" y="{cy + i * (size + 3):.0f}" font-size="{size}" text-anchor="middle" '
                              f'paint-order="stroke" stroke="#ffffff" stroke-width="5" stroke-linejoin="round" '
                              f'fill="{lcol or col}">{escape(ln)}</text>')

    def text(self, x, y, s, size=13, col=MUTED, anchor="start", bold=False):
        wt = ' font-weight="bold"' if bold else ""
        self.o.append(f'<text x="{x}" y="{y}" font-size="{size}"{wt} text-anchor="{anchor}" fill="{col}">{escape(s)}</text>')

    def legend(self, x, y, items):
        for i, (col, dash, label) in enumerate(items):
            yy = y + i * 22
            da = f' stroke-dasharray="{dash}"' if dash else ""
            self.o.append(f'<line x1="{x}" y1="{yy}" x2="{x + 44}" y2="{yy}" stroke="{col}" stroke-width="2.5"{da}/>')
            self.text(x + 54, yy + 5, label, 13, "#333")

    def save(self, name):
        self.o.append("</svg>")
        (OUT / name).write_text("\n".join(self.o) + "\n")
        return OUT / name


def fig4():
    s = Svg(1240, 880, "oneM2M and ETSI MEC in EdgeFollow: who talks to whom")
    s.area(40, 60, 1160, 150, "Cloud")
    s.box(420, 92, 400, 96, ["IN-CSE (ACME 2026.5.3)", "AEs: handover orchestrator, context hub,",
                             "learning orchestrator; route = announced AE"])
    for x, edge, cse in ((40, "A", "ACME 2026.5.3"), (630, "B", "ACME, or tinyIoT (section 9)")):
        s.area(x, 250, 570, 400, f"Edge {edge}")
        s.box(x + 20, 285, 220, 80, [f"MN-CSE {edge}", cse])
        s.box(x + 60, 430, 180, 90, ["MEC applications", "each is also", "a oneM2M AE"], stroke=MEC, fill=MECFILL, size=13)
        s.area(x + 330, 285, 220, 250, "MEC platform", stroke="#9bb7dc", fill="#f5f9fe")
        for j, (svc, what) in enumerate((("MEC 011", "app support"), ("MEC 012", "radio network info"),
                                         ("MEC 013", "location"), ("MEC 046", "sensor sharing"))):
            s.box(x + 342, 318 + j * 52, 196, 44, [svc, what], stroke=MEC, fill=MECFILL, size=13)
        s.arrow(x + 150, 430, x + 150, 367, M2M, "aK", "Mca", lx=x + 175, ly=405)
        s.arrow(x + 242, 475, x + 340, 475, MEC, "aB", "Mp1", lx=x + 290, ly=467)
        s.arrow(x + 340, 330, x + 242, 330, MEC, "aB", ["reads device", "data as an AE"], lx=x + 290, ly=300, size=11)
    s.arrow(150, 283, 520, 190, M2M, "aK", both=True)
    s.arrow(770, 283, 720, 190, M2M, "aK", both=True)
    s.text(300, 238, "Mcc", 13, M2M, bold=True)
    s.text(765, 238, "Mcc", 13, M2M, bold=True)
    s.arrow(588, 600, 652, 600, MEC, "aB", "MEC 040 federation: peers and the target edge", both=True, ly=588)
    s.box(40, 700, 270, 70, ["phone-A, the vehicle", "app: AE with rr=false, polling"], size=13)
    s.box(330, 700, 270, 70, ["phone-B, roadside sensor", "app: stays on edge A"], size=13)
    s.arrow(80, 700, 80, 367, USB, "aG", dash="7 5")
    s.o.append(f'<polyline points="465,700 465,620 93,620 93,372" fill="none" stroke="{USB}" stroke-width="2" '
               f'stroke-dasharray="7 5" marker-end="url(#aG)"/>')
    s.text(104, 612, "Mca: HTTP over USB in the lab", 12, MUTED)
    s.box(860, 700, 340, 70, ["MEC 010-2 lifecycle (Mm1)", "state of MEC apps, both edges;",
                              "a platform agent starts them"], stroke=MEC, fill=MECFILL, size=13)
    s.arrow(1030, 700, 1030, 652, MEC, "aB", "Mm1", lx=1060, ly=680)
    s.legend(40, 805, [(M2M, None, "oneM2M: Mca (device or app to its CSE), Mcc (CSE to CSE)"),
                       (MEC, None, "ETSI MEC: Mp1 (app to platform), Mm1 (lifecycle), federation"),
                       (USB, "7 5", "lab only: the phones reach edge A over USB, not over the radio")])
    return s.save("figure_onem2m_mec.svg")


def fig5():
    s = Svg(1240, 640, "TR-0086 deployment options, as EdgeFollow runs them")
    panels = [
        ("A", ["the location proxy as a MEC app,", "registered at the IN-CSE"], "no MN-CSE; 21 tests",
         [(["IN-CSE"], M2M, BOXFILL), (["location proxy", "a MEC app and an AE"], MEC, MECFILL), (["MEC 013"], MEC, MECFILL)]),
        ("B", ["an MN-CSE beside", "the MEC services"], "the lab itself; no tests of its own",
         [(["IN-CSE"], M2M, BOXFILL), (["MN-CSE"], M2M, BOXFILL), (["MEC services"], MEC, MECFILL)]),
        ("C", ["the MN-CSE runs as", "a MEC application"], "MEC 010-2 lifecycle; C and D: 101 tests",
         [(["IN-CSE"], M2M, BOXFILL), (["MN-CSE", "as a MEC app"], MEC, MECFILL), (["MEC 010-2", "and the platform agent"], MEC, MECFILL)]),
        ("D", ["that MN-CSE, offered", "as a MEC service"], "found through MEC 011",
         [(["IN-CSE"], M2M, BOXFILL), (["MN-CSE as the service", "onem2m-mn-cse"], MEC, MECFILL), (["a consumer app", "finds it in MEC 011"], MEC, MECFILL)]),
    ]
    for i, (opt, what, note, boxes) in enumerate(panels):
        x = 30 + i * 300
        s.area(x, 70, 280, 490, f"Option {opt}")
        for j, ln in enumerate(what):
            s.text(x + 140, 108 + j * 18, ln, 13, INK, "middle", bold=True)
        for k, (lbl, st, fl) in enumerate(boxes):
            y = 160 + k * 120
            s.box(x + 30, y, 220, 64, lbl, stroke=st, fill=fl, size=13)
            if k:
                col, mk = (M2M, "aK") if k == 1 else (MEC, "aB")
                s.arrow(x + 140, y, x + 140, y - 54, col, mk)
        s.text(x + 140, 540, note, 12, MUTED, "middle")
    s.legend(30, 595, [(M2M, None, "oneM2M registration (Mca for an AE, Mcc for an MN-CSE)"),
                       (MEC, None, "MEC: Mp1, Mm1 lifecycle, or service discovery in MEC 011")])
    return s.save("figure_deployment_options.svg")


def fig6():
    s = Svg(1240, 900, "The move in the handover library, with its route checks")
    steps = [
        ("1  Checks before", "target reachable, registered at the IN-CSE, ready in MEC 011; route = the source alone"),
        ("2  Lock", "a transaction container on the IN-CSE, with an expiry"),
        ("3  Create the AE on the target", "with announcement to the IN-CSE (at, aa)"),
        ("4  Route check", "the IN routes the vehicle to source AND target, nothing else (wait up to 2 s)"),
        ("5  Copy and verify", "containers, every sample, access control policies, subscriptions"),
        ("6  Route check again", "still source and target"),
        ("7  Resume the device on the target", "then forget the rollback list"),
        ("8  Release the source", "DELETE on the source edge"),
        ("9  Final check", "the IN routes to the target alone, and the source is gone"),
    ]
    y = 70
    for i, (a, b) in enumerate(steps):
        st, fl = (HI, HIFILL) if i in (3, 5, 8) else (M2M, BOXFILL)
        s.box(60, y, 620, 66, [a, b], stroke=st, fill=fl, size=14, anchor="start")
        if i < len(steps) - 1:
            s.arrow(370, y + 66, 370, y + 82, M2M, "aK")
        if i == 3:
            s.arrow(680, y + 33, 800, y + 33, BAD, "aR", "no", lx=740, ly=y + 25)
        if i == 5:
            s.o.append(f'<polyline points="680,{y + 33} 760,{y + 33} 760,430 798,430" fill="none" stroke="{BAD}" '
                       f'stroke-width="2" marker-end="url(#aR)"/>')
            s.text(720, y + 25, "no", 12, BAD, "middle")
        y += 82
    s.box(800, 300, 400, 150, ["ROLLED BACK (not moved)", "the target copy is deleted;", "the source keeps everything;",
                               "the device stays on edge A"], stroke=BAD, fill=BADFILL)
    s.arrow(680, 70 + 8 * 82 + 33, 800, 70 + 8 * 82 + 33, BAD, "aR", "no", lx=740, ly=70 + 8 * 82 + 25)
    s.box(800, 650, 400, 110, ["INCONSISTENT (reported, not success)", "nothing is rolled back after the release:",
                               "every copy is kept, so nothing is lost"], stroke=BAD, fill=BADFILL)
    s.arrow(370, 70 + 8 * 82 + 66, 370, 830, OK, "aE")
    s.box(220, 830, 300, 50, ["MOVED"], stroke=OK, fill=OKFILL)
    s.text(800, 500, "Why steps 4, 6 and 9 exist: with tinyIoT as edge B,", 13, INK)
    s.text(800, 520, "the AE was created (201) but its announcement", 13, INK)
    s.text(800, 540, "never reached the IN-CSE, and the old code", 13, INK)
    s.text(800, 560, "reported success with no route at all.", 13, INK)
    s.text(800, 586, "Records: tinyiot run2 (the fault), commit 37fdfb9 (the fix).", 12, MUTED)
    return s.save("figure_route_checks.svg")


def fig7():
    s = Svg(1240, 700, "One move, two oneM2M implementations: ACME and tinyIoT")
    s.box(420, 70, 400, 150, ["IN-CSE (ACME 2026.5.3)", "one CSEBaseAnnc per edge", "announced AE of the vehicle",
                              "= the route the move checks"], size=14)
    s.box(80, 330, 320, 110, ["MN-CSE A", "ACME 2026.5.3", "/id-mn-a"])
    s.box(840, 330, 320, 110, ["MN-CSE B", "tinyIoT c140495, same identity", "/id-mn-b"], stroke=HI, fill=HIFILL)
    s.arrow(400, 370, 840, 370, M2M, "aK", "ACME -> tinyIoT: PASS", ly=360)
    s.arrow(840, 410, 400, 410, M2M, "aK", "tinyIoT -> ACME: PASS", ly=430)
    s.arrow(240, 330, 480, 220, M2M, "aK", ["announces", "the AE"], lx=330, ly=262)
    s.arrow(1000, 330, 760, 220, M2M, "aK", ["announces", "the AE"], lx=910, ly=262)
    s.text(620, 470, "Full scenario with MEC 013, 012 and 040, tinyIoT as edge B: 10 of 10 steps (2026-11-21)", 14, INK,
           "middle", bold=True)
    s.box(80, 520, 1080, 130, ["Found on the way, in tinyIoT (to be reported)",
                               "after a restart with a fresh database, its CSEBaseAnnc at the IN already exists: the IN answers 409;",
                               "tinyIoT then guesses the name /id-in/-/id-mn-b_cba, which it never asked for: 404; the AE is still",
                               "created (201), but no announcement reaches the IN. The library's route checks now refuse such a move."],
          stroke=BAD, fill=BADFILL, size=14, anchor="start")
    return s.save("figure_two_implementations.svg")


def fig8():
    s = Svg(1240, 720, "ETSI's hosted MEC Sandbox drives the move")
    s.area(30, 70, 560, 560, "ETSI MEC Sandbox (hosted by ETSI, 8 network scenarios)", stroke="#9bb7dc", fill="#f5f9fe")
    for k, (zx, zy, z) in enumerate(((60, 110, "zone01"), (320, 110, "zone02"), (60, 300, "zone03"), (320, 300, "zone04"))):
        s.box(zx, zy, 240, 160, [z, "radio cells (Wi-Fi in some scenarios)"], stroke="#9bb7dc", fill="#ffffff", size=13)
    s.o.append(f'<circle cx="250" cy="260" r="9" fill="{HI}"/>')
    s.arrow(250, 300, 360, 220, HI, "aO", ["a simulated user", "drives into the", "next zone"], lx=330, ly=290, size=11)
    s.box(60, 500, 500, 100, ["MEC 013 location API", "on mep1 (and mep2 in two-platform scenarios):",
                              "which zone serves each user"], stroke=MEC, fill=MECFILL, size=13)
    s.box(700, 120, 480, 120, ["Driver on the lab PC", "asks MEC 013 every 2 s (HTTPS);",
                               "when the followed user enters the next zone: move"], size=14)
    s.arrow(560, 550, 700, 200, MEC, "aB", ["polled: the Sandbox", "cannot call my PC"], lx=640, ly=420, size=12)
    s.box(700, 300, 480, 80, ["Handover library", "with the route checks of figure 5"], size=14)
    s.arrow(940, 240, 940, 300, M2M, "aK")
    s.box(700, 440, 220, 90, ["MN-CSE A", "zone A's edge"], size=14)
    s.box(960, 440, 220, 90, ["MN-CSE B", "zone B's edge"], size=14)
    s.arrow(920, 485, 960, 485, M2M, "aK")
    s.arrow(940, 380, 810, 440, M2M, "aK")
    s.arrow(940, 380, 1070, 440, M2M, "aK")
    s.text(700, 576, "9 of 10 runs completed, in all 8 scenarios;", 14, INK, bold=True)
    s.text(700, 597, "each move took 0.24 to 0.30 s; edge A answered 404 afterwards;", 13, INK)
    s.text(700, 617, "the tenth run correctly did not move.", 13, INK)
    s.text(700, 643, "Polled, so the trigger is up to 2 s late; the users are simulated.", 13, MUTED)
    s.text(700, 665, "Records: records/sandbox/ (the Sandbox's address is not published).", 12, MUTED)
    return s.save("figure_sandbox_driven.svg")


def fig9():
    # (binding, write median, write p95, notify ms or None, notify kind)
    rows = [("HTTP", 3.83, 5.65, 12.09, "poll"), ("HTTPS", 16.28, 17.66, 23.78, "poll"),
            ("WebSocket", 2.90, 3.77, 4.47, "push"), ("WebSocket + TLS", 2.90, 4.07, 4.46, "push"),
            ("MQTT (broker)", 4.00, 5.21, 47.7, "push"), ("CoAP", 2.90, 4.02, 15.43, "poll")]
    W, H = 1240, 640
    s = Svg(W, H, "One oneM2M workload over six bindings of one CSE (ACME 2026.5.3, loopback)")
    # panel A: write latency
    x0, x1, top, rowh = 230, 560, 110, 62
    s.text(30, 90, "A  Write one 100 B sample, ms: median (bar), p95 (tick)", 15, INK, bold=True)
    scale = (x1 - x0) / 20.0
    for g in range(0, 21, 5):
        gx = x0 + g * scale
        s.o.append(f'<line x1="{gx:.0f}" y1="{top - 8}" x2="{gx:.0f}" y2="{top + len(rows) * rowh}" stroke="{GRID}" stroke-width="1"/>')
        s.text(gx, top + len(rows) * rowh + 18, str(g), 12, MUTED, "middle")
    for i, (name, med, p95, _, _) in enumerate(rows):
        y = top + i * rowh + 14
        s.text(x0 - 12, y + 16, name, 14, INK, "end")
        s.o.append(f'<rect x="{x0}" y="{y}" width="{med * scale:.1f}" height="24" rx="4" fill="#6b6b6b"/>')
        s.o.append(f'<line x1="{x0 + p95 * scale:.1f}" y1="{y - 4}" x2="{x0 + p95 * scale:.1f}" y2="{y + 28}" stroke="{INK}" stroke-width="2"/>')
        s.text(x0 + p95 * scale + 8, y + 17, f"{med:.1f} / {p95:.1f}", 12, "#333")
    # panel B: getting a command to a device nobody can call
    x0, x1 = 760, 1180
    s.text(640, 90, "B  A notification to a device that nobody can call, ms", 15, INK, bold=True)
    scale = (x1 - x0) / 100.0
    for g in range(0, 101, 25):
        gx = x0 + g * scale
        s.o.append(f'<line x1="{gx:.0f}" y1="{top - 8}" x2="{gx:.0f}" y2="{top + len(rows) * rowh}" stroke="{GRID}" stroke-width="1"/>')
        s.text(gx, top + len(rows) * rowh + 18, str(g), 12, MUTED, "middle")
    for i, (name, _, _, ms, kind) in enumerate(rows):
        y = top + i * rowh + 14
        s.text(x0 - 12, y + 16, name, 14, INK, "end")
        col = MEC if kind == "push" else HI
        s.o.append(f'<rect x="{x0}" y="{y}" width="{ms * scale:.1f}" height="24" rx="4" fill="{col}"/>')
        if "MQTT" in name:   # 47 ms after an isolated write; 92 ms when writes follow each other (lighter extension)
            s.o.append(f'<rect x="{x0 + ms * scale:.1f}" y="{y}" width="{(91.85 - ms) * scale:.1f}" height="24" rx="4" '
                       f'fill="#9bb7dc"/>')
            s.text(x0 + 6, y + 17, "48 isolated write", 12, "#ffffff")
            s.text(x0 + 91.85 * scale - 6, y + 17, "92 back to back", 12, INK, "end")
            continue
        lab = f"{ms:.1f}  {'pushed on its own connection' if kind == 'push' else 'polling channel'}"
        s.text(x0 + ms * scale + 8, y + 17, lab, 12, "#333")
    s.o.append(f'<rect x="700" y="{H - 120}" width="16" height="16" rx="3" fill="{MEC}"/>')
    s.text(724, H - 107, "push: the CSE sends on a connection the device opened", 13, "#333")
    s.o.append(f'<rect x="700" y="{H - 94}" width="16" height="16" rx="3" fill="{HI}"/>')
    s.text(724, H - 81, "poll: the device holds a request open (pollingChannel)", 13, "#333")
    s.text(30, H - 52, "CoAP: ACME sends no notifications over CoAP, so the device must poll. HTTPS: the repeated TLS handshake is about", 13, MUTED)
    s.text(30, H - 32, "1.5 ms of its extra cost; about 11 ms is server time this run does not explain. MQTT: cause of the delay not found.", 13, MUTED)
    s.text(30, H - 12, "Record: records/proto/proto_bench_20261121T033502Z_public.json (3 repeats; one PC, loopback: not a network measurement).", 12, MUTED)
    return s.save("figure_protocols.svg")


if __name__ == "__main__":
    for f in (fig4, fig5, fig6, fig7, fig8, fig9):
        print(f())
