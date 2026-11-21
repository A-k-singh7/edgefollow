// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ashish Kumar Singh
package org.edgefollow.probe;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.SystemClock;
import android.telephony.CellIdentityLte;
import android.telephony.CellIdentityNr;
import android.telephony.CellInfo;
import android.telephony.CellInfoLte;
import android.telephony.CellInfoNr;
import android.telephony.CellSignalStrengthLte;
import android.telephony.CellSignalStrengthNr;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Foreground "location" service: every `period` seconds it snapshots IMU/env sensors,
 * GNSS/network location, serving+neighbour cells and Wi-Fi, writes the snapshot
 * locally (latest.json only; no on-device history) and posts it to a oneM2M CSE as contentInstances
 * under AE `phone` (or extra `rn`): containers imu, env, loc, radio, wlan.
 */
public class LiveService extends Service implements SensorEventListener, LocationListener {
    static final String TAG = "probe-live";
    HandlerThread bg;
    Handler h;
    File out;
    String cse;      // e.g. http://127.0.0.1:8201/cse-mn-a
    String origin;   // e.g. Cphone-DEVC
    String rn = "phone";  // AE resource name (extra `rn`, v18; default "phone" = v16 behaviour)
    int periodS;
    boolean running;
    int seq;
    final Map<Integer, double[]> acc = new HashMap<>();   // type -> [n, s0..s5, last0..last5]
    final Map<String, Location> locs = new HashMap<>();
    boolean aeReady;
    int postOk, postFail, tsOk, tsFail, cmds;
    Thread poller;
    // v20: socket factory that trusts only lab_ca.crt; null = none (http CSE, or the file is not usable).
    volatile javax.net.ssl.SSLSocketFactory labTls;

    @Override public IBinder onBind(Intent i) { return null; }

    @Override
    public int onStartCommand(Intent it, int flags, int startId) {
        if (it != null && "stop".equals(it.getStringExtra("cmd"))) { stopAll(); return START_NOT_STICKY; }
        if (running) {
            // Re-point a running service instead of ignoring the new target (found 2026-09-28:
            // a running service kept posting to the old CSE, so a handover "back" never happened).
            String nc = it == null ? null : it.getStringExtra("cse");
            String no = it == null ? null : it.getStringExtra("origin");
            String nr = it == null ? null : validRn(it.getStringExtra("rn"));
            if ((nc != null && !nc.equals(cse)) || (nr != null && !nr.equals(rn))) {
                labTls = null;  // v20: never use the old factory while the target changes
                if (nc != null) cse = nc;
                if (no != null) origin = no;
                if (nr != null) rn = nr;
                if (it.hasExtra("period")) periodS = it.getIntExtra("period", periodS);
                aeReady = false;  // ensureAe() runs against the new CSE on the next cycle
                loadLabCa();
                log("repoint cse=" + cse + " origin=" + origin + ("phone".equals(rn) ? "" : " rn=" + rn));
            }
            return START_STICKY;
        }
        running = true;
        out = getExternalFilesDir(null);
        cse = it == null ? null : it.getStringExtra("cse");
        origin = it == null || it.getStringExtra("origin") == null ? "Cphone" : it.getStringExtra("origin");
        periodS = it == null ? 5 : it.getIntExtra("period", 5);
        if (it != null && validRn(it.getStringExtra("rn")) != null) rn = validRn(it.getStringExtra("rn"));
        loadLabCa();

        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("live", "probe live", NotificationManager.IMPORTANCE_LOW));
        Notification n = new Notification.Builder(this, "live").setContentTitle("probe: live telemetry")
                .setSmallIcon(android.R.drawable.ic_menu_mylocation).build();
        startForeground(1, n);

        bg = new HandlerThread("live-bg");
        bg.start();
        h = new Handler(bg.getLooper());
        SensorManager sm = getSystemService(SensorManager.class);
        int[] types = {Sensor.TYPE_ACCELEROMETER, Sensor.TYPE_GYROSCOPE, Sensor.TYPE_MAGNETIC_FIELD,
                Sensor.TYPE_LIGHT, Sensor.TYPE_PROXIMITY, Sensor.TYPE_ROTATION_VECTOR};
        for (int t : types) {
            Sensor s = sm.getDefaultSensor(t);
            if (s != null) sm.registerListener(this, s, 20_000, h);
        }
        LocationManager lm = getSystemService(LocationManager.class);
        for (String p : new String[]{LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, "fused"}) {
            try {
                if (lm.getAllProviders().contains(p)) lm.requestLocationUpdates(p, 1000L, 0f, this, bg.getLooper());
            } catch (SecurityException | IllegalArgumentException e) { log("loc provider " + p + " " + e); }
        }
        h.postDelayed(this::tick, 1000);
        log("live started cse=" + cse + " origin=" + origin + " period=" + periodS + ("phone".equals(rn) ? "" : " rn=" + rn));
        return START_STICKY;
    }

    /** AE resource names go into a URL path and a JSON body: accept only [A-Za-z0-9_-]{1,64}. */
    static String validRn(String s) {
        return s != null && s.matches("[A-Za-z0-9_-]{1,64}") ? s : null;
    }

    void stopAll() {
        running = false;
        try { getSystemService(SensorManager.class).unregisterListener(this); } catch (Exception ignored) { }
        try { getSystemService(LocationManager.class).removeUpdates(this); } catch (Exception ignored) { }
        log("live stopped seq=" + seq + " postOk=" + postOk + " postFail=" + postFail);
        stopForeground(true);
        stopSelf();
        if (bg != null) bg.quitSafely();
    }

    void log(String s) {
        Log.i(TAG, s);
        try (FileWriter w = new FileWriter(new File(getExternalFilesDir(null), "live_status.txt"), true)) {
            w.write(System.currentTimeMillis() + " " + s + "\n");
        } catch (Exception ignored) { }
    }

    // ------------------------------------------------------------ inputs
    @Override public void onSensorChanged(SensorEvent e) {
        double[] a = acc.get(e.sensor.getType());
        if (a == null) { a = new double[13]; acc.put(e.sensor.getType(), a); }
        a[0]++;
        for (int i = 0; i < 6; i++) {
            double v = i < e.values.length ? e.values[i] : 0;
            a[1 + i] += v;
            a[7 + i] = v;
        }
    }
    @Override public void onAccuracyChanged(Sensor s, int a) { }
    @Override public void onLocationChanged(Location l) { locs.put(l.getProvider(), l); }
    @Override public void onProviderEnabled(String p) { }
    @Override public void onProviderDisabled(String p) { }
    @Override public void onStatusChanged(String p, int s, Bundle b) { }

    // ------------------------------------------------------------ snapshot
    void tick() {
        if (!running) return;
        TelephonyManager tm = getSystemService(TelephonyManager.class);
        try {
            tm.requestCellInfoUpdate(Executors.newSingleThreadExecutor(), new TelephonyManager.CellInfoCallback() {
                @Override public void onCellInfo(List<CellInfo> cells) { h.post(() -> emit(cells, null)); }
                @Override public void onError(int code, Throwable detail) { h.post(() -> emit(null, "cellinfo error " + code)); }
            });
        } catch (SecurityException e) {
            emit(null, "cellinfo " + e);
        }
        h.postDelayed(this::tick, periodS * 1000L);
    }

    void emit(List<CellInfo> cells, String cellErr) {
        try {
            long now = System.currentTimeMillis();
            JSONObject imu = new JSONObject(), env = new JSONObject();
            String[] names = {"accel", "gyro", "mag", "light", "proximity", "rotvec"};
            int[] types = {Sensor.TYPE_ACCELEROMETER, Sensor.TYPE_GYROSCOPE, Sensor.TYPE_MAGNETIC_FIELD,
                    Sensor.TYPE_LIGHT, Sensor.TYPE_PROXIMITY, Sensor.TYPE_ROTATION_VECTOR};
            for (int i = 0; i < types.length; i++) {
                double[] a = acc.get(types[i]);
                JSONObject s = new JSONObject();
                if (a != null && a[0] > 0) {
                    JSONArray mean = new JSONArray(), last = new JSONArray();
                    int k = (types[i] == Sensor.TYPE_LIGHT || types[i] == Sensor.TYPE_PROXIMITY) ? 1
                            : types[i] == Sensor.TYPE_ROTATION_VECTOR ? 4 : 3;
                    for (int j = 0; j < k; j++) { mean.put(a[1 + j] / a[0]); last.put(a[7 + j]); }
                    s.put("n", (long) a[0]).put("mean", mean).put("last", last);
                    for (int j = 0; j < 7; j++) a[j] = 0;  // reset window, keep last
                } else {
                    s.put("n", 0);
                }
                (i < 3 || i == 5 ? imu : env).put(names[i], s);
            }
            imu.put("t", now);

            Intent bat = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if (bat != null) {
                env.put("battery_pct", bat.getIntExtra(BatteryManager.EXTRA_LEVEL, -1));
                env.put("battery_temp_c", bat.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) / 10.0);
            }
            env.put("t", now);

            JSONObject loc = new JSONObject();
            for (Map.Entry<String, Location> e : locs.entrySet()) {
                Location l = e.getValue();
                JSONObject o = new JSONObject().put("lat", l.getLatitude()).put("lon", l.getLongitude())
                        .put("acc_m", l.hasAccuracy() ? l.getAccuracy() : JSONObject.NULL)
                        .put("alt_m", l.hasAltitude() ? l.getAltitude() : JSONObject.NULL)
                        .put("age_s", (SystemClock.elapsedRealtimeNanos() - l.getElapsedRealtimeNanos()) / 1e9)
                        .put("t", l.getTime());
                loc.put(e.getKey(), o);
            }
            loc.put("t", now);

            JSONObject radio = new JSONObject();
            TelephonyManager tm = getSystemService(TelephonyManager.class);
            radio.put("operator", tm.getNetworkOperatorName()).put("plmn", tm.getNetworkOperator());
            try {
                ServiceState ss = tm.getServiceState();
                if (ss != null) radio.put("earfcn", ss.getChannelNumber()).put("state", ss.getState())
                        .put("bw_khz", new JSONArray(ss.getCellBandwidths()));
            } catch (SecurityException e) { radio.put("serviceState", "denied"); }
            JSONArray cl = new JSONArray();
            if (cells != null) for (CellInfo c : cells) cl.put(cellJson(c));
            radio.put("cells", cl);
            if (cellErr != null) radio.put("error", cellErr);
            radio.put("t", now);

            JSONObject wlan = new JSONObject();
            WifiManager wm = getApplicationContext().getSystemService(WifiManager.class);
            WifiInfo wi = wm.getConnectionInfo();
            if (wi != null) wlan.put("ssid", wi.getSSID()).put("bssid", wi.getBSSID()).put("rssi", wi.getRssi())
                    .put("freq", wi.getFrequency()).put("link_mbps", wi.getLinkSpeed())
                    .put("rx_mbps", wi.getRxLinkSpeedMbps()).put("tx_mbps", wi.getTxLinkSpeedMbps())
                    .put("standard", wi.getWifiStandard()).put("net_id", wi.getNetworkId());
            try {
                android.net.ConnectivityManager cm = getSystemService(android.net.ConnectivityManager.class);
                JSONArray ips = new JSONArray();
                for (android.net.Network nw : cm.getAllNetworks()) {
                    android.net.NetworkCapabilities nc = cm.getNetworkCapabilities(nw);
                    android.net.LinkProperties lp = cm.getLinkProperties(nw);
                    if (nc != null && lp != null && nc.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI))
                        for (android.net.LinkAddress la : lp.getLinkAddresses()) ips.put(la.getAddress().getHostAddress());
                }
                wlan.put("ip", ips);
            } catch (Exception e) { wlan.put("ip_error", e.toString()); }
            JSONArray scan = new JSONArray();
            try {
                for (ScanResult r : wm.getScanResults()) {
                    JSONObject o = new JSONObject().put("ssid", r.SSID).put("bssid", r.BSSID).put("rssi", r.level)
                            .put("freq", r.frequency).put("width", r.channelWidth).put("center0", r.centerFreq0)
                            .put("standard", r.getWifiStandard()).put("caps", r.capabilities)
                            .put("age_ms", (SystemClock.elapsedRealtime() * 1000 - r.timestamp) / 1000);
                    // IEEE 802.11 BSS Load element (id 11): station count (2 LE), channel
                    // utilization (1, /255), available admission capacity (2 LE, 32 us/s units).
                    for (ScanResult.InformationElement ie : r.getInformationElements()) {
                        if (ie.getId() == 11) {
                            java.nio.ByteBuffer b = ie.getBytes().order(java.nio.ByteOrder.LITTLE_ENDIAN);
                            if (b.remaining() >= 5)
                                o.put("bss_load", new JSONObject().put("sta_count", b.getShort() & 0xffff)
                                        .put("chan_util", b.get() & 0xff).put("avail_adm_cap", b.getShort() & 0xffff));
                        }
                    }
                    scan.put(o);
                }
            } catch (SecurityException e) { wlan.put("scan", "denied"); }
            wlan.put("neighbours", scan).put("t", now);

            JSONObject all = new JSONObject().put("seq", seq).put("t", now).put("imu", imu).put("env", env)
                    .put("loc", loc).put("radio", radio).put("wlan", wlan);
            try (FileWriter w = new FileWriter(new File(out, "latest.json"))) { w.write(all.toString(1)); }

            if (cse != null && !(isHttps(cse) && labTls == null)) {  // v20: https without the lab CA posts nothing
                if (!aeReady) aeReady = ensureAe();
                if (aeReady) {
                    post("imu", imu); post("env", env); post("loc", loc); post("radio", radio); post("wlan", wlan);
                    postTs(radio, now);
                }
            }
            if (seq % 12 == 0) log("seq " + seq + " cells=" + cl.length() + " locs=" + locs.keySet()
                    + " postOk=" + postOk + " postFail=" + postFail + " tsOk=" + tsOk + " tsFail=" + tsFail + " cmds=" + cmds);
            seq++;
        } catch (Exception e) {
            log("emit error " + Log.getStackTraceString(e));
        }
    }

    static JSONObject cellJson(CellInfo c) throws Exception {
        JSONObject o = new JSONObject().put("registered", c.isRegistered());
        if (c instanceof CellInfoLte) {
            CellIdentityLte id = ((CellInfoLte) c).getCellIdentity();
            CellSignalStrengthLte s = ((CellInfoLte) c).getCellSignalStrength();
            o.put("rat", "LTE").put("mcc", id.getMccString()).put("mnc", id.getMncString())
             .put("ci", id.getCi()).put("pci", id.getPci()).put("tac", id.getTac())
             .put("earfcn", id.getEarfcn()).put("bw_khz", id.getBandwidth())
             .put("rsrp", s.getRsrp()).put("rsrq", s.getRsrq()).put("rssnr", s.getRssnr())
             .put("rssi", s.getRssi()).put("cqi", s.getCqi()).put("ta", s.getTimingAdvance())
             .put("dbm", s.getDbm()).put("level", s.getLevel());
        } else if (c instanceof CellInfoNr) {
            CellIdentityNr id = (CellIdentityNr) ((CellInfoNr) c).getCellIdentity();
            CellSignalStrengthNr s = (CellSignalStrengthNr) ((CellInfoNr) c).getCellSignalStrength();
            o.put("rat", "NR").put("mcc", id.getMccString()).put("mnc", id.getMncString())
             .put("nci", id.getNci()).put("pci", id.getPci()).put("tac", id.getTac())
             .put("nrarfcn", id.getNrarfcn()).put("ss_rsrp", s.getSsRsrp()).put("ss_rsrq", s.getSsRsrq())
             .put("ss_sinr", s.getSsSinr()).put("dbm", s.getDbm());
        } else {
            o.put("rat", c.getClass().getSimpleName()).put("raw", c.toString());
        }
        return o;
    }

    // ------------------------------------------------------------ oneM2M
    boolean ensureAe() {
        // rr=false: a phone is NOT request-reachable; downlink goes through a pollingChannel.
        int ae = http("POST", cse, 2, "{\"m2m:ae\":{\"rn\":\"" + rn + "\",\"api\":\"Nprobe.phone\",\"rr\":false,\"srv\":[\"4\"]}}");
        // 403/409 = this originator is already registered; reuse it if it resolves
        boolean ok = ae == 201 || http("GET", cse + "/" + rn, 0, null) == 200;
        if (ae != 201) http("PUT", cse + "/" + rn, 0, "{\"m2m:ae\":{\"rr\":false}}");
        for (String c : new String[]{"imu", "env", "loc", "radio", "wlan", "cmd", "ack"}) {
            int r = http("POST", cse + "/" + rn, 3, "{\"m2m:cnt\":{\"rn\":\"" + c + "\",\"mni\":2000}}");
            ok &= r == 201 || r == 409;
        }
        int pch = http("POST", cse + "/" + rn, 15, "{\"m2m:pch\":{\"rn\":\"pch\"}}");
        int sub = http("POST", cse + "/" + rn + "/cmd", 23, "{\"m2m:sub\":{\"rn\":\"cmdSub\",\"nu\":[\"" + origin
                + "\"],\"enc\":{\"net\":[3]},\"nct\":1}}");
        log("ensureAe ok=" + ok + " ae=" + ae + " pch=" + pch + " cmdSub=" + sub);
        if (ok && poller == null) {
            poller = new Thread(this::pollLoop, "pcu-poller");
            poller.start();
        }
        return ok;
    }

    // ------------------------------------------------------------ downlink
    // Long-poll the pollingChannel; each notification about a new <cmd> instance is a
    // command: {"cmd":"ping"|"period","id":..,"value":..}. The result goes to <ack>.
    void pollLoop() {
        while (running) {
            try {
                String[] r = httpBody("GET", cse + "/" + rn + "/pch/pcu", 0, null, 30000);
                if (!"200".equals(r[0]) || r[1].isEmpty()) { Thread.sleep(500); continue; }
                JSONObject rq = new JSONObject(r[1]);
                JSONObject sgn = find(rq, "m2m:sgn");
                String rqi = findString(rq, "rqi");
                if (rqi != null) httpBody("POST", cse + "/" + rn + "/pch/pcu", 0,
                        new JSONObject().put("m2m:rsp", new JSONObject().put("rsc", 2000).put("rqi", rqi)
                                .put("rvi", "4").put("to", cse)).toString(), 5000);
                if (sgn == null) { Thread.sleep(1000); continue; }  // nothing queued: back off, never busy-loop
                if (sgn.optBoolean("vrq")) continue;
                JSONObject cin = find(sgn, "m2m:cin");
                if (cin == null) continue;
                JSONObject cmd = new JSONObject(cin.getString("con"));
                JSONObject ack = new JSONObject().put("id", cmd.opt("id")).put("cmd", cmd.optString("cmd"))
                        .put("phone_t", System.currentTimeMillis());
                switch (cmd.optString("cmd")) {
                    case "ping":
                        Intent bat = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
                        ack.put("ok", true).put("battery_pct", bat == null ? -1 : bat.getIntExtra(BatteryManager.EXTRA_LEVEL, -1));
                        break;
                    case "period":
                        int v = cmd.optInt("value", periodS);
                        if (v >= 1 && v <= 60) { periodS = v; ack.put("ok", true).put("period", periodS); }
                        else ack.put("ok", false).put("error", "period out of range 1..60");
                        break;
                    default:
                        ack.put("ok", false).put("error", "unknown command");
                }
                cmds++;
                post("ack", ack);
                log("cmd " + cmd + " -> " + ack);
            } catch (Exception e) {
                try { Thread.sleep(1000); } catch (InterruptedException ignored) { }
            }
        }
    }

    static JSONObject find(Object o, String key) {
        if (o instanceof JSONObject) {
            JSONObject j = (JSONObject) o;
            if (j.opt(key) instanceof JSONObject) return j.optJSONObject(key);
            for (java.util.Iterator<String> it = j.keys(); it.hasNext(); ) {
                JSONObject r = find(j.opt(it.next()), key);
                if (r != null) return r;
            }
        } else if (o instanceof JSONArray) {
            JSONArray a = (JSONArray) o;
            for (int i = 0; i < a.length(); i++) { JSONObject r = find(a.opt(i), key); if (r != null) return r; }
        }
        return null;
    }

    static String findString(Object o, String key) {
        if (o instanceof JSONObject) {
            JSONObject j = (JSONObject) o;
            if (j.opt(key) instanceof String) return j.optString(key);
            for (java.util.Iterator<String> it = j.keys(); it.hasNext(); ) {
                String r = findString(j.opt(it.next()), key);
                if (r != null) return r;
            }
        }
        return null;
    }

    // timeSeries: if <radioTs> exists, every radio sample is also a <tsi> carrying its real
    // dataGenerationTime, so the CSE can detect missing samples by itself.
    static final java.text.SimpleDateFormat DGT = new java.text.SimpleDateFormat("yyyyMMdd'T'HHmmss','SSS'000'");
    static { DGT.setTimeZone(java.util.TimeZone.getTimeZone("UTC")); }

    void postTs(JSONObject radio, long t) throws Exception {
        JSONObject sc = null;
        JSONArray cells = radio.optJSONArray("cells");
        for (int i = 0; cells != null && i < cells.length(); i++)
            if (cells.getJSONObject(i).optBoolean("registered")) { sc = cells.getJSONObject(i); break; }
        JSONObject con = new JSONObject().put("seq", seq).put("rsrp", sc == null ? JSONObject.NULL : sc.opt("rsrp"));
        String dgt;
        synchronized (DGT) { dgt = DGT.format(new java.util.Date(t)); }
        int r = http("POST", cse + "/" + rn + "/radioTs", 30, new JSONObject().put("m2m:tsi",
                new JSONObject().put("dgt", dgt).put("snr", seq).put("con", con.toString())).toString());
        if (r == 201) tsOk++; else if (r != 404) tsFail++;
    }

    void post(String cnt, JSONObject con) throws Exception {
        JSONObject cin = new JSONObject().put("m2m:cin", new JSONObject().put("cnf", "application/json:0").put("con", con.toString()));
        int r = http("POST", cse + "/" + rn + "/" + cnt, 4, cin.toString());
        if (r == 201) postOk++;
        else {
            postFail++;
            // 404: our registration is gone (data erased, CSE restarted with an in-memory store)
            // -> register again on the next sample. 403 means REFUSED (e.g. MEC 033 revoked us)
            // and must not be "fixed" by re-registering.
            if (r == 404 && aeReady) { aeReady = false; log("registration gone (404) -> will re-register"); }
        }
    }

    // ------------------------------------------------------------ v20: lab CA for an https CSE
    static boolean isHttps(String url) { return url != null && url.regionMatches(true, 0, "https:", 0, 6); }

    /** Called at service start and on every re-point. For an https CSE: build a socket factory whose
     *  only trust anchor is the single certificate in lab_ca.crt (app external files dir). No system
     *  CAs, no fallback: on any error labTls stays null and nothing is sent to that CSE. */
    void loadLabCa() {
        labTls = null;
        if (!isHttps(cse)) return;
        try (InputStream in = new java.io.FileInputStream(new File(getExternalFilesDir(null), "lab_ca.crt"))) {
            java.util.Collection<? extends java.security.cert.Certificate> cs =
                    java.security.cert.CertificateFactory.getInstance("X.509").generateCertificates(in);
            if (cs.size() != 1) throw new java.security.cert.CertificateException("need exactly 1 certificate, got " + cs.size());
            java.security.KeyStore trust = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
            trust.load(null, null);
            trust.setCertificateEntry("lab", cs.iterator().next());
            javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            labTls = ctx.getSocketFactory();
            log("https cse: trusting only lab_ca.crt");
        } catch (Exception e) {
            log("https cse but lab_ca.crt not usable (" + e.getClass().getSimpleName() + "): nothing will be posted");
        }
    }

    /** The only place this service opens a connection. http: exactly as v19. https: the lab CA
     *  factory or an exception, never the platform default trust. Host name check = platform default. */
    HttpURLConnection open(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        if (c instanceof javax.net.ssl.HttpsURLConnection) {
            javax.net.ssl.SSLSocketFactory f = labTls;
            if (f == null) throw new java.io.IOException("https without lab CA");
            ((javax.net.ssl.HttpsURLConnection) c).setSSLSocketFactory(f);
        }
        return c;
    }

    String[] httpBody(String method, String url, int ty, String body, int readTimeoutMs) throws Exception {
        HttpURLConnection c = open(url);
        c.setConnectTimeout(3000); c.setReadTimeout(readTimeoutMs);
        c.setRequestMethod(method);
        c.setRequestProperty("X-M2M-Origin", origin);
        c.setRequestProperty("X-M2M-RI", "q" + SystemClock.elapsedRealtimeNanos());
        c.setRequestProperty("X-M2M-RVI", "4");
        c.setRequestProperty("Accept", "application/json");
        if (body != null) {
            c.setRequestProperty("Content-Type", ty > 0 ? "application/json;ty=" + ty : "application/json");
            c.setDoOutput(true);
            try (OutputStream o = c.getOutputStream()) { o.write(body.getBytes(StandardCharsets.UTF_8)); }
        }
        int code = c.getResponseCode();
        StringBuilder sb = new StringBuilder();
        try (InputStream in = code < 400 ? c.getInputStream() : c.getErrorStream()) {
            if (in != null) { byte[] b = new byte[4096]; for (int n; (n = in.read(b)) > 0; ) sb.append(new String(b, 0, n, StandardCharsets.UTF_8)); }
        }
        c.disconnect();
        return new String[]{String.valueOf(code), sb.toString()};
    }

    int http(String method, String url, int ty, String body) {
        try {
            HttpURLConnection c = open(url);
            c.setConnectTimeout(3000); c.setReadTimeout(5000);
            c.setRequestMethod(method);
            c.setRequestProperty("X-M2M-Origin", origin);
            c.setRequestProperty("X-M2M-RI", "p" + SystemClock.elapsedRealtime());
            c.setRequestProperty("X-M2M-RVI", "4");
            c.setRequestProperty("Accept", "application/json");
            if (body != null) {
                c.setRequestProperty("Content-Type", ty > 0 ? "application/json;ty=" + ty : "application/json");
                c.setDoOutput(true);
                try (OutputStream o = c.getOutputStream()) { o.write(body.getBytes(StandardCharsets.UTF_8)); }
            }
            int code = c.getResponseCode();
            try (InputStream in = code < 400 ? c.getInputStream() : c.getErrorStream()) { if (in != null) while (in.read() >= 0) { } }
            c.disconnect();
            return code;
        } catch (Exception e) {
            return -1;
        }
    }

    @Override public void onDestroy() { running = false; super.onDestroy(); }
}
