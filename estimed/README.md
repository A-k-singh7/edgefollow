# ESTIMED Hackathon #2 -- oneM2M topology

The oneM2M half of the prototype: one cloud CSE and two edge CSEs, which is the
substrate the MEC federation handover runs on top of.

    IN-CSE    id-in     cse-in     :8200    cloud, durable resource tree
    MN-CSE-A  id-mn-a   cse-mn-a   :8201    edge A  -> registered to the IN
    MN-CSE-B  id-mn-b   cse-mn-b   :8202    edge B  -> registered to the IN

Implementation: **ACME oneM2M CSE 2026.5.3** (pinned in `requirements.txt`; 2026.5.1 until 2026-10-29) (BSD-3-Clause), chosen over Eclipse
OM2M because it is Python -- the same stack as the MEC candidates -- and its licence
sits cleanly alongside this repo.

## Run

```
bash run_topology.sh     # starts all three, waits for each to answer
bash stop_topology.sh    # stops them and frees the ports
```

Ports 8200-8202 were picked to avoid every port the MEC candidates use
(3004-3005, 8081-8111).

Configs are versioned here in `conf/`; runtime data, logs and PID files live
**outside the repo** under `/home/edgefollow/estimed-run/`, so nothing untracked can
land in the working tree. The venv is `/home/edgefollow/estimed-venv`, deliberately
separate from `edgefollow-lab/.venv` that the MEC candidates share -- breaking
that venv would take down the whole 55-suite conformance sweep.

## Verified working

```
$ curl .../cse-in?fu=1&ty=16          # remoteCSE resources at the IN
{"m2m:uril": ["cse-in/id-mn-a", "cse-in/id-mn-b"]}

$ curl .../cse-in/id-mn-a             # the CSR the IN holds for edge A
  ri: id-mn-a   csi: /id-mn-a   cst: 2 (MN)   ty: 16   poa: ['http://127.0.0.1:8201']

$ POST .../cse-mn-a  (ty=2)           # a vehicle AE on edge A
  HTTP 201, aei: Cvehicle01
```

## Five things that cost time, recorded so they don't again

**1. `--headless` suppresses the error that explains why headless failed.**
A misconfigured CSE prints only the banner and exits **0**. `Configuration._print`
is a no-op when `_args_headless` is set, so the "Configuration Error" never
appears. The configs therefore set `[logging] enableFileLogging=true`, which is
what makes headless operation diagnosable. To surface a config error directly:

```python
CM.Configuration._print = staticmethod(lambda m, markup=True: print(m))
CM.Configuration.init(parseArgs())
```

**2. `consoleType` must be `rich` or `simple`.** `headless` is not a value -- that
is the separate `--headless` flag.

**3. An IN-CSE must not have a registrar.** `RemoteCSEServiceConfiguration` rejects
any registrar `cseID` other than `/`, so `registrarCseID` is left **empty** in
`in.ini` while the MNs point at the IN.

**4. `allowedCSROriginators` is empty by default**, so an MN's registration is
refused with **RSC 4103** (`has no CREATE privileges`). The registrar must list its
registrees -- and the ids need a **leading slash**. `acme.ini.default` documents the
key as *"CSE-IDs must not have a leading /"*, but the validator rejects that form:

    Invalid originator: "id-mn-a" ... Must be a CSE-ID in absolute or SP-relative form

SP-relative means `/id-mn-a`. **The template's comment and its validator disagree** --
follow the validator.

**5. Record the CSE's own pid, not `$!`.** `$!` is the pid of `setsid`; the CSE is
its child, one higher. Recording the wrong pid made `stop_topology.sh` silently kill
nothing: the old generation kept the ports, every restart died with *"Port already
in use"*, and health checks answered from the stale process -- so a config fix looked
like it had no effect. `run_topology.sh` resolves the real pid from `/proc`.

**And never `pkill -f <pattern>` here.** Commands run via `bash -c "<cmd>"`, so the
pattern is in the invoking shell's own argv and `pkill` kills the shell. That cost
three runs before it was spotted. The same trap applies to the `CANDMARK` tokens: a marker argument that ETSI's
test-suite runner (not in this repository) passes to a MEC candidate so that it can find the process again.

## The scenario

```
EDGEFOLLOW_PY=<lab python> bash mec_services.sh start   # MEC 012 :8085, MEC 013 :8101, MEC 040 :8300
bash run_topology.sh             # IN-CSE + 2 MN-CSEs
python3 scenario.py              # the demo;  --json for machine-readable output
```

`handover.py` (step 4a) is the oneM2M half on its own -- move a vehicle's subtree
MN-A → MN-B and prove nothing is lost. It carries no MEC dependency **on purpose**:
if it fails, the fault is unambiguously oneM2M-side.

`scenario.py` (step 4b) puts the MEC services in front, so they decide *whether* to
hand over and *where to*:

| step | service | contributes |
|---|---|---|
| where is the vehicle | MEC 013 Location `:8101` | zone, access point, lat/long |
| is a handover due | MEC 012 RNIS `:8085` | serving cell from `rab_info` |
| which peer system | MEC 040 Federation `:8300` | peer `systemId` **and its `endpoint`** |
| execute | oneM2M `:8201`→`:8202` | AE + container + contentInstances |

**10/10 steps pass, three consecutive runs.**

The `endpoint` attribute is what makes federation discovery actionable: without it
the answer names a peer but not where it is, and the handover has nowhere to go.
That is why `demo/mec040.py` adds it.

> **Conformance note, added after checking the published API.** `SystemInfo`
> (x-etsi-ref 6.2.2 in `MEC040_fedEnablement.yaml` on ETSI Forge) has exactly
> `systemId`, `systemName` and `systemProvider`. It has **no `endpoint`**. The
> attribute does exist in GS MEC 040, but on `SystemInfoUpdate` (6.2.3), and it is
> typed `EndPointInfo` (8.1.5.3) -- an object with `uris[]`, `fqdn[]`,
> `addresses[]` -- **not a string**.
>
> So the `"endpoint": "<url>"` string this fork seeds is a **non-conformant local
> extension on two counts**: wrong resource type, and wrong value type. It is
> useful for the demo and it is not what the standard says. The conformance
> candidate `mec040/` does not carry it, which is why the two remain separable and
> why the sweep is unaffected.


### Scope, stated plainly

MEC 040's ATS surface is `fed_resources/system_info`: federation **discovery**, not
app-instance transfer. The scenario uses it for exactly what it is -- the peer lookup
that tells the handover where to go. Claiming more would misrepresent it.

### Why federation is the interesting axis

ESTIMED publishes six use cases -- autonomous vehicles, future home, industrial
digital twins, metaverse smart shopping, smart city, smart warehouse. Checked
against all six: **none mentions MEC federation, inter-MEC-system communication,
multi-operator scenarios or roaming.** Continuity across a journey is precisely
where an edge handover stops being intra-system, so MEC 040 is what makes
"continuous edge computing" more than a single-operator demo.

## ⚠️ The resource name is not agreed, and that is measured

Checked 2026-08-31 against ETSI's own published definition and ETSI's own live sandbox:

| source | apiName | resource |
|---|---|---|
| GS MEC 040 OpenAPI (`main` = `v3.1.1`) | `fed_enablement` | `fed_resources/system_info` |
| ETSI ATS release 3.3.1 | `fed-enablement` | `fed_resources/system_info` |
| ETSI live sandbox | `fed_enablement` | **`fed_resources/systems`** |

Each of ETSI's two artefacts deviates from ETSI's own API definition, in a **different**
place, so **the ATS and the sandbox share no path** — `system_info` 404s on the sandbox,
and `systems` appears in neither the spec nor the ATS. There is no published v3.3.1 of
this API; "3.3.1" is the MEC *release* number, not the API version.

Consequences here, and only here:

- `estimed/scenario.py` sets `FED_BASE` (override with `EDGEFOLLOW_FED_BASE`) and tries
  `fed_resources/system_info` **first**, falling back to `fed_resources/systems`. The
  spec-conformant name stays the default; the sandbox spelling is the fallback, never the
  other way round. If neither serves a list it returns `[]`, so a federation failure stays
  visible instead of being coerced into a fake peer.
- `demo/mec040.py` routes both apiName spellings inbound.
- 🚫 **The MEC 040 conformance candidate (not in this repository) is untouched and stays exactly
  ATS-shaped.** Its 20/29 score against ETSI's test suite is only meaningful if it keeps failing what the
  ATS fails. Do not port this tolerance into it.

Verified with a stand-in server on each spelling (client picks the right one, and returns
nothing when neither is served) and against the real `demo/mec040.py`.

## ETSI's MEC Sandbox

The dual-path MEC 040 client above is verified against local stand-ins. The Sandbox itself drives the move:
`estimed/sandbox_follow.py` polls a live Sandbox session's MEC 013 every 2 s and moves the vehicle when it
enters the next zone. On 2026-11-21 that move completed in all 8 of the Sandbox's network scenarios (9 of 10
runs; the tenth correctly did not move); the records are in `records/sandbox/`. A Sandbox session id expires,
and a 401 from the portal means "unknown or expired id", not an authentication gate.
