"""Reverse cross-implementation handover: the vehicle starts on edge B (tinyIoT on :8202) and moves to edge A
(ACME on :8201), with the committed estimed/handover.py. Same checks as handover.py's own main(), mirrored."""
import sys
sys.path.insert(0, "/home/edgefollow/edgefollow/estimed")
import handover as h  # noqa: E402

ok = True
h.reset()
print("1. edges registered at the IN-CSE")
edges = h.registered_edges(); print(f"     {edges}"); ok &= h.edges_ok(edges)
print("2. vehicle joins edge B (tinyIoT)")
st, _ = h.create_ae(h.EDGE_B); print(f"     AE        HTTP {st}"); ok &= st in (201, 409)
st, _ = h.create_container(h.EDGE_B); print(f"     container HTTP {st}"); ok &= st in (201, 409)
samples = ["48.1351,11.5820", "48.1361,11.5835", "48.1372,11.5849"]
for s in samples:
    ok &= h.add_sample(h.EDGE_B, s)[0] == 201
print(f"     {len(samples)} position samples written")
print("3. subtree readable on edge B")
before = h.read_samples(h.EDGE_B); print(f"     {before}"); ok &= before == samples
print("4. handover B -> A")
moved = h.handover(h.EDGE_B, h.EDGE_A, before); print(f"     {'done' if moved else 'FAILED'}"); ok &= moved
print("5. subtree readable on edge A, and gone from B")
after = h.read_samples(h.EDGE_A); print(f"     on A: {after}"); ok &= after == samples
st, _ = h._req("GET", f"{h.EDGE_B[0]}/{h.EDGE_B[1]}/{h.AE_NAME}", h.AE_ORIGIN)
print(f"     on B: HTTP {st} (404 expected)"); ok &= st == 404
print("6. IN-CSE still holds both edges")
edges = h.registered_edges(); print(f"     {edges}"); ok &= h.edges_ok(edges)
h.reset()
print(f"\n  RESULT: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
