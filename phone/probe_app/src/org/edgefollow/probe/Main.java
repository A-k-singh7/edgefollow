// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ashish Kumar Singh
package org.edgefollow.probe;

import android.app.Activity;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.ImageFormat;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureFailure;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.CaptureResult;
import android.hardware.camera2.DngCreator;
import android.hardware.camera2.TotalCaptureResult;
import android.hardware.camera2.params.BlackLevelPattern;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.BatteryManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;
import android.util.Size;
import android.view.WindowManager;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Headless measurement probe, driven by `am start -e mode <info|sensors|raw|live|live-stop|mec016|attest|sign|sign_prompt|capture|clock> ...`.
 * Everything lands under getExternalFilesDir(null); a `done_<mode>` file marks completion.
 */
public class Main extends Activity {
    static final String TAG = "probe";
    File out;
    HandlerThread bg;
    Handler h;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        // Immersive: no nav/status bar to catch stray touches while the phone lies face-down.
        getWindow().getDecorView().setSystemUiVisibility(android.view.View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                | android.view.View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | android.view.View.SYSTEM_UI_FLAG_FULLSCREEN
                | android.view.View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION | android.view.View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN);
        out = getExternalFilesDir(null);
        bg = new HandlerThread("probe-bg");
        bg.start();
        h = new Handler(bg.getLooper());
        dispatch(getIntent());
    }

    /** A command sent while an earlier instance is still on top arrives here, not in onCreate.
     *  Found 2026-09-28 on Android 16: without this, back-to-back `am start` commands (live-stop,
     *  then live -> another CSE) were dropped silently and the phone never re-pointed. */
    @Override
    protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        setIntent(i);
        dispatch(i);
    }

    void dispatch(final Intent it) {
        String mode = it.getStringExtra("mode");
        if (mode == null) mode = "info";
        final String m = mode;
        new File(out, "done_" + m).delete();
        new Thread(() -> {
            try {
                switch (m) {
                    case "info": info(); break;
                    case "sensors": sensors(it.getIntExtra("dur", 60)); break;
                    case "raw": raw(it.getStringExtra("cam"), it.getIntExtra("iso", 100),
                            it.getLongExtra("exp", 10_000_000L), it.getIntExtra("n", 40),
                            it.getIntExtra("maxw", 4000), it.getStringExtra("tag")); break;
                    case "live": {
                        Intent s = new Intent(this, LiveService.class);
                        s.putExtra("cse", it.getStringExtra("cse"));
                        s.putExtra("origin", it.getStringExtra("origin"));
                        s.putExtra("period", it.getIntExtra("period", 5));
                        if (it.getStringExtra("rn") != null) s.putExtra("rn", it.getStringExtra("rn"));
                        startForegroundService(s);
                        status("live service start requested");
                        break;
                    }
                    case "mec016": mec016(it.getStringExtra("base"), it.getStringExtra("dev"),
                            it.getBooleanExtra("switch", false), it.getBooleanExtra("cleanup", true)); break;
                    case "attest":
                        if (it.hasExtra("auth") || it.hasExtra("timeout") || it.hasExtra("invalidate")
                                || it.hasExtra("unlocked") || it.hasExtra("alias")) attestBound(it);
                        else attest(it.getStringExtra("challenge"), it.getBooleanExtra("strongbox", false));
                        break;
                    case "sign": sign(it.getStringExtra("alias"), it.getStringExtra("challenge")); break;
                    case "sign_prompt": signPrompt(it.getStringExtra("alias"), it.getStringExtra("challenge"),
                            it.getStringExtra("authn")); break;
                    case "capture": capture(it); break;
                    case "clock": clock(intExtra(it, "n", 50)); break;
                    case "live-stop":
                        startService(new Intent(this, LiveService.class).putExtra("cmd", "stop"));
                        status("live service stop requested");
                        break;
                    default: status("unknown mode " + m);
                }
                touch("done_" + m);
            } catch (Throwable t) {
                status("ERROR " + Log.getStackTraceString(t));
                touch("done_" + m);
            }
            // v19: while a capture runs, a concurrent command must not finish() the activity (that would
            // drop FLAG_KEEP_SCREEN_ON and background the app, stopping continuous sensor delivery).
            // With no capture running this is the v18 behaviour.
            if (m.equals("capture") || !capturing) runOnUiThread(this::finish);
        }).start();
    }

    void status(String s) {
        Log.i(TAG, s);
        try (FileWriter w = new FileWriter(new File(out, "status.txt"), true)) {
            w.write(System.currentTimeMillis() + " " + s + "\n");
        } catch (IOException ignored) { }
    }

    void touch(String name) {
        try { new FileOutputStream(new File(out, name)).close(); } catch (IOException ignored) { }
    }

    static String q(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }

    // ---------------------------------------------------------------- info
    void info() throws Exception {
        SensorManager sm = getSystemService(SensorManager.class);
        StringBuilder sb = new StringBuilder("[\n");
        List<Sensor> all = sm.getSensorList(Sensor.TYPE_ALL);
        for (int i = 0; i < all.size(); i++) {
            Sensor s = all.get(i);
            sb.append("{\"name\":").append(q(s.getName()))
              .append(",\"vendor\":").append(q(s.getVendor()))
              .append(",\"type\":").append(s.getType())
              .append(",\"stringType\":").append(q(s.getStringType()))
              .append(",\"id\":").append(s.getId())
              .append(",\"version\":").append(s.getVersion())
              .append(",\"resolution\":").append(s.getResolution())
              .append(",\"maxRange\":").append(s.getMaximumRange())
              .append(",\"power_mA\":").append(s.getPower())
              .append(",\"minDelay_us\":").append(s.getMinDelay())
              .append(",\"maxDelay_us\":").append(s.getMaxDelay())
              .append(",\"fifoReserved\":").append(s.getFifoReservedEventCount())
              .append(",\"fifoMax\":").append(s.getFifoMaxEventCount())
              .append(",\"reportingMode\":").append(s.getReportingMode())
              .append(",\"wakeUp\":").append(s.isWakeUpSensor())
              .append(",\"dynamic\":").append(s.isDynamicSensor())
              .append("}").append(i + 1 < all.size() ? ",\n" : "\n");
        }
        sb.append("]\n");
        write("sensors.json", sb.toString());

        CameraManager cm = getSystemService(CameraManager.class);
        sb = new StringBuilder("[\n");
        String[] ids = cm.getCameraIdList();
        for (int i = 0; i < ids.length; i++) {
            CameraCharacteristics c = cm.getCameraCharacteristics(ids[i]);
            StreamConfigurationMap map = c.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            Size[] raw = map == null ? null : map.getOutputSizes(ImageFormat.RAW_SENSOR);
            BlackLevelPattern bl = c.get(CameraCharacteristics.SENSOR_BLACK_LEVEL_PATTERN);
            sb.append("{\"id\":").append(q(ids[i]))
              .append(",\"facing\":").append(c.get(CameraCharacteristics.LENS_FACING))
              .append(",\"raw_sizes\":").append(q(Arrays.toString(raw)))
              .append(",\"iso_range\":").append(q(String.valueOf(c.get(CameraCharacteristics.SENSOR_INFO_SENSITIVITY_RANGE))))
              .append(",\"exp_range_ns\":").append(q(String.valueOf(c.get(CameraCharacteristics.SENSOR_INFO_EXPOSURE_TIME_RANGE))))
              .append(",\"cfa\":").append(c.get(CameraCharacteristics.SENSOR_INFO_COLOR_FILTER_ARRANGEMENT))
              .append(",\"white\":").append(c.get(CameraCharacteristics.SENSOR_INFO_WHITE_LEVEL))
              .append(",\"black\":").append(q(String.valueOf(bl)))
              .append(",\"pixel_array\":").append(q(String.valueOf(c.get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE))))
              .append(",\"physical_mm\":").append(q(String.valueOf(c.get(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE))))
              .append(",\"focal\":").append(q(Arrays.toString(c.get(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS))))
              .append(",\"caps\":").append(q(Arrays.toString(c.get(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES))))
              .append(",\"physical_ids\":").append(q(String.valueOf(c.getPhysicalCameraIds())))
              .append(",\"hw_level\":").append(c.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL))
              .append("}").append(i + 1 < ids.length ? ",\n" : "\n");
        }
        sb.append("]\n");
        write("cameras.json", sb.toString());
        status("info written");
    }

    void write(String name, String s) throws IOException {
        try (FileWriter w = new FileWriter(new File(out, name))) { w.write(s); }
    }

    // ------------------------------------------------------------- sensors
    void sensors(int durS) throws Exception {
        SensorManager sm = getSystemService(SensorManager.class);
        File f = new File(out, "sensors_" + System.currentTimeMillis() + ".csv");
        final BufferedWriter w = new BufferedWriter(new FileWriter(f), 1 << 20);
        w.write("id,type,t_event_ns,t_recv_ns,accuracy,v0,v1,v2,v3,v4,v5\n");
        final long[] count = new long[1];
        SensorEventListener l = new SensorEventListener() {
            @Override public void onSensorChanged(SensorEvent e) {
                StringBuilder sb = new StringBuilder(96);
                sb.append(e.sensor.getId()).append(',').append(e.sensor.getType()).append(',')
                  .append(e.timestamp).append(',').append(SystemClock.elapsedRealtimeNanos()).append(',')
                  .append(e.accuracy);
                for (int i = 0; i < 6; i++) sb.append(',').append(i < e.values.length ? Float.toString(e.values[i]) : "");
                sb.append('\n');
                synchronized (w) {
                    try { w.write(sb.toString()); } catch (IOException ignored) { }
                    count[0]++;
                }
            }
            @Override public void onAccuracyChanged(Sensor s, int a) { }
        };
        int reg = 0;
        StringBuilder regd = new StringBuilder();
        for (Sensor s : sm.getSensorList(Sensor.TYPE_ALL)) {
            if (s.isWakeUpSensor() || s.getReportingMode() == Sensor.REPORTING_MODE_ONE_SHOT) continue;
            if (sm.registerListener(l, s, SensorManager.SENSOR_DELAY_FASTEST, h)) {
                reg++; regd.append(s.getId()).append(':').append(s.getName()).append("; ");
            } else {
                status("register FAILED " + s.getName());
            }
        }
        status("sensors registered " + reg + ": " + regd);
        long end = SystemClock.elapsedRealtime() + durS * 1000L;
        while (SystemClock.elapsedRealtime() < end) {
            Thread.sleep(5000);
            synchronized (w) { status("events " + count[0]); }
        }
        sm.unregisterListener(l);
        Thread.sleep(300);
        synchronized (w) { w.close(); }
        status("sensors done file=" + f.getName() + " events=" + count[0]);
    }

    // -------------------------------------------------------------- mec016
    // The phone as the MEC 016 device application: every request/response it makes is
    // logged verbatim to mec016_log.json; optionally it re-points its own telemetry to the
    // referenceURI the edge returned.
    org.json.JSONArray m16log;

    String[] http(String method, String url, String body) throws Exception {
        java.net.HttpURLConnection c = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
        c.setConnectTimeout(4000); c.setReadTimeout(8000);
        c.setRequestMethod(method);
        c.setRequestProperty("Accept", "application/json");
        if (body != null) {
            c.setRequestProperty("Content-Type", "application/json");
            c.setDoOutput(true);
            try (java.io.OutputStream o = c.getOutputStream()) { o.write(body.getBytes("UTF-8")); }
        }
        int code = c.getResponseCode();
        String resp = "";
        try (java.io.InputStream in = code < 400 ? c.getInputStream() : c.getErrorStream()) {
            if (in != null) resp = new String(readAll(in), "UTF-8");
        }
        c.disconnect();
        m16log.put(new org.json.JSONObject().put("method", method).put("url", url)
                .put("request", body == null ? org.json.JSONObject.NULL : body).put("status", code).put("response", resp)
                .put("t", System.currentTimeMillis()));
        return new String[]{String.valueOf(code), resp};
    }

    static byte[] readAll(java.io.InputStream in) throws IOException {
        java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        for (int n; (n = in.read(buf)) > 0; ) b.write(buf, 0, n);
        return b.toByteArray();
    }

    void mec016(String base, String dev, boolean sw, boolean cleanup) throws Exception {
        if (base == null) base = "http://127.0.0.1:8411/dev_app/v1";
        if (dev == null) dev = "probe-" + android.os.Build.SERIAL;
        m16log = new org.json.JSONArray();
        String app = "{\"appName\":\"estimed-telemetry\",\"appProvider\":\"edgefollow\",\"appDVersion\":\"v1\"";
        try {
            http("GET", base + "/app_list?appName=estimed-telemetry", null);
            http("POST", base + "/obtain_app_loc_availability",
                    "{\"associateDevAppId\":\"" + dev + "\",\"appInfo\":" + app + "}}");
            String[] ctx = http("POST", base + "/app_contexts", "{\"associateDevAppId\":\"" + dev
                    + "\",\"appLocationUpdates\":false,\"appAutoInstantiation\":false,\"appInfo\":" + app
                    + ",\"userAppInstanceInfo\":[{}]}}");
            if ("201".equals(ctx[0])) {
                org.json.JSONObject c = new org.json.JSONObject(ctx[1]);
                String uri = c.getJSONObject("appInfo").getJSONArray("userAppInstanceInfo").getJSONObject(0).getString("referenceURI");
                status("mec016 context " + c.getString("contextId") + " -> " + uri);
                if (sw) {
                    startService(new Intent(this, LiveService.class).putExtra("cmd", "stop"));
                    Thread.sleep(1500);
                    Intent s = new Intent(this, LiveService.class);
                    s.putExtra("cse", uri);
                    s.putExtra("origin", "Cphone-DEVC");
                    s.putExtra("period", 5);
                    startForegroundService(s);
                    status("mec016 telemetry re-pointed to " + uri);
                }
                if (cleanup) http("DELETE", base + "/app_contexts/" + c.getString("contextId"), null);
            }
        } finally {
            write("mec016_log.json", m16log.toString(1));
        }
    }

    // ----------------------------------------------------------------- raw
    void raw(String camId, int iso, long expNs, int n, int maxW, String tag) throws Exception {
        CameraManager cm = getSystemService(CameraManager.class);
        if (camId == null) camId = "0";
        final CameraCharacteristics ch = cm.getCameraCharacteristics(camId);
        StreamConfigurationMap map = ch.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
        Size best = null;
        for (Size s : map.getOutputSizes(ImageFormat.RAW_SENSOR)) {
            if (s.getWidth() <= maxW && (best == null || s.getWidth() > best.getWidth())) best = s;
        }
        if (best == null) throw new IllegalStateException("no RAW_SENSOR size <= " + maxW);
        File dir = new File(out, "raw_" + (tag == null ? "run" : tag));
        dir.mkdirs();
        status("raw cam=" + camId + " size=" + best + " iso=" + iso + " exp_ns=" + expNs + " n=" + n + " dir=" + dir.getName());

        final BlockingQueue<Image> images = new ArrayBlockingQueue<>(4);
        final BlockingQueue<Object> results = new ArrayBlockingQueue<>(4);
        ImageReader reader = ImageReader.newInstance(best.getWidth(), best.getHeight(), ImageFormat.RAW_SENSOR, 3);
        reader.setOnImageAvailableListener(r -> {
            Image im = r.acquireNextImage();
            if (im != null && !images.offer(im)) im.close();
        }, h);

        final BlockingQueue<Object> devQ = new ArrayBlockingQueue<>(1);
        cm.openCamera(camId, new CameraDevice.StateCallback() {
            @Override public void onOpened(CameraDevice d) { devQ.offer(d); }
            @Override public void onDisconnected(CameraDevice d) { devQ.offer("disconnected"); d.close(); }
            @Override public void onError(CameraDevice d, int e) { devQ.offer("error " + e); d.close(); }
        }, h);
        Object o = devQ.poll(15, TimeUnit.SECONDS);
        if (!(o instanceof CameraDevice)) throw new IllegalStateException("open failed: " + o);
        final CameraDevice dev = (CameraDevice) o;

        final BlockingQueue<Object> sessQ = new ArrayBlockingQueue<>(1);
        dev.createCaptureSession(Arrays.asList(reader.getSurface()), new CameraCaptureSession.StateCallback() {
            @Override public void onConfigured(CameraCaptureSession s) { sessQ.offer(s); }
            @Override public void onConfigureFailed(CameraCaptureSession s) { sessQ.offer("configure failed"); }
        }, h);
        o = sessQ.poll(15, TimeUnit.SECONDS);
        if (!(o instanceof CameraCaptureSession)) throw new IllegalStateException("session: " + o);
        CameraCaptureSession sess = (CameraCaptureSession) o;

        CaptureRequest.Builder rb = dev.createCaptureRequest(CameraDevice.TEMPLATE_MANUAL);
        rb.addTarget(reader.getSurface());
        rb.set(CaptureRequest.CONTROL_MODE, CaptureRequest.CONTROL_MODE_OFF);
        rb.set(CaptureRequest.CONTROL_AE_MODE, CaptureRequest.CONTROL_AE_MODE_OFF);
        rb.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_OFF);
        rb.set(CaptureRequest.CONTROL_AWB_MODE, CaptureRequest.CONTROL_AWB_MODE_OFF);
        rb.set(CaptureRequest.FLASH_MODE, CaptureRequest.FLASH_MODE_OFF);
        rb.set(CaptureRequest.LENS_FOCUS_DISTANCE, 0f);
        rb.set(CaptureRequest.LENS_OPTICAL_STABILIZATION_MODE, CaptureRequest.LENS_OPTICAL_STABILIZATION_MODE_OFF);
        rb.set(CaptureRequest.NOISE_REDUCTION_MODE, CaptureRequest.NOISE_REDUCTION_MODE_OFF);
        rb.set(CaptureRequest.HOT_PIXEL_MODE, CaptureRequest.HOT_PIXEL_MODE_OFF);
        rb.set(CaptureRequest.BLACK_LEVEL_LOCK, true);
        rb.set(CaptureRequest.SENSOR_SENSITIVITY, iso);
        rb.set(CaptureRequest.SENSOR_EXPOSURE_TIME, expNs);
        rb.set(CaptureRequest.SENSOR_FRAME_DURATION, Math.max(expNs + 5_000_000L, 50_000_000L));
        CaptureRequest req = rb.build();

        CameraCaptureSession.CaptureCallback cb = new CameraCaptureSession.CaptureCallback() {
            @Override public void onCaptureCompleted(CameraCaptureSession s, CaptureRequest r, TotalCaptureResult res) { results.offer(res); }
            @Override public void onCaptureFailed(CameraCaptureSession s, CaptureRequest r, CaptureFailure f) { results.offer("failed reason=" + f.getReason()); }
        };

        StringBuilder meta = new StringBuilder("frame,iso,exp_ns,sensor_ts,black_lock,dyn_black,dyn_white,temp_note\n");
        long timeoutMs = Math.max(10_000L, expNs / 1_000_000L * 4);
        for (int i = 0; i < n; i++) {
            sess.capture(req, cb, h);
            Object r = results.poll(timeoutMs, TimeUnit.MILLISECONDS);
            Image im = images.poll(timeoutMs, TimeUnit.MILLISECONDS);
            if (!(r instanceof TotalCaptureResult) || im == null) {
                status("frame " + i + " FAILED result=" + r + " image=" + im);
                if (im != null) im.close();
                continue;
            }
            TotalCaptureResult tr = (TotalCaptureResult) r;
            if (best.equals(ch.get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE))) {
                File f = new File(dir, String.format("f%03d.dng", i));
                try (FileOutputStream fo = new FileOutputStream(f)) {
                    new DngCreator(ch, tr).writeImage(fo, im);
                }
            } else {
                // DngCreator only accepts pixel-array-sized buffers; a binned RAW_SENSOR
                // stream is written verbatim: little-endian uint16, rows packed (stride removed).
                Image.Plane pl = im.getPlanes()[0];
                java.nio.ByteBuffer buf = pl.getBuffer();
                int w = im.getWidth(), hgt = im.getHeight(), stride = pl.getRowStride();
                byte[] row = new byte[w * 2];
                File f = new File(dir, String.format("f%03d.raw16", i));
                try (java.io.BufferedOutputStream fo = new java.io.BufferedOutputStream(new FileOutputStream(f), 1 << 20)) {
                    for (int y = 0; y < hgt; y++) {
                        buf.position(y * stride);
                        buf.get(row);
                        fo.write(row);
                    }
                }
                if (i == 0) {
                    write(dir.getName() + "_format.json", "{\"width\":" + w + ",\"height\":" + hgt
                            + ",\"cfa\":" + ch.get(CameraCharacteristics.SENSOR_INFO_COLOR_FILTER_ARRANGEMENT)
                            + ",\"white\":" + ch.get(CameraCharacteristics.SENSOR_INFO_WHITE_LEVEL)
                            + ",\"black_static\":" + q(String.valueOf(ch.get(CameraCharacteristics.SENSOR_BLACK_LEVEL_PATTERN)))
                            + ",\"dyn_black\":" + q(Arrays.toString(tr.get(CaptureResult.SENSOR_DYNAMIC_BLACK_LEVEL)))
                            + ",\"dyn_white\":" + tr.get(CaptureResult.SENSOR_DYNAMIC_WHITE_LEVEL)
                            + ",\"camera\":" + q(camId) + "}\n");
                }
            }
            im.close();
            meta.append(i).append(',').append(tr.get(CaptureResult.SENSOR_SENSITIVITY)).append(',')
                .append(tr.get(CaptureResult.SENSOR_EXPOSURE_TIME)).append(',')
                .append(tr.get(CaptureResult.SENSOR_TIMESTAMP)).append(',')
                .append(tr.get(CaptureResult.BLACK_LEVEL_LOCK)).append(',')
                .append(q(Arrays.toString(tr.get(CaptureResult.SENSOR_DYNAMIC_BLACK_LEVEL)))).append(',')
                .append(tr.get(CaptureResult.SENSOR_DYNAMIC_WHITE_LEVEL)).append(",\n");
            status("frame " + i + " ok iso=" + tr.get(CaptureResult.SENSOR_SENSITIVITY)
                    + " exp=" + tr.get(CaptureResult.SENSOR_EXPOSURE_TIME));
        }
        write(dir.getName() + "_meta.csv", meta.toString());
        sess.close();
        dev.close();
        reader.close();
        status("raw done " + dir.getName());
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (bg != null) bg.quitSafely();
    }
    /** Android Keystore key attestation (TEE/StrongBox): EC P-256 key with the caller's challenge,
     *  exported chain + a proof-of-possession signature over the challenge; the key is deleted after. */
    void attest(String challengeHex, boolean strongbox) throws Exception {
        if (challengeHex == null || challengeHex.length() % 2 != 0) throw new IllegalArgumentException("challenge hex required");
        byte[] ch = new byte[challengeHex.length() / 2];
        for (int i = 0; i < ch.length; i++) ch[i] = (byte) Integer.parseInt(challengeHex.substring(2 * i, 2 * i + 2), 16);
        String alias = "probe-attest-" + System.currentTimeMillis();
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance(
                android.security.keystore.KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        android.security.keystore.KeyGenParameterSpec.Builder b = new android.security.keystore.KeyGenParameterSpec.Builder(
                alias, android.security.keystore.KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(ch);
        if (strongbox) b.setIsStrongBoxBacked(true);
        kpg.initialize(b.build());
        java.security.KeyPair kp = kpg.generateKeyPair();
        java.security.KeyStore ks = java.security.KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
        java.security.Signature sg = java.security.Signature.getInstance("SHA256withECDSA");
        sg.initSign(kp.getPrivate());
        sg.update(ch);
        byte[] pop = sg.sign();
        StringBuilder j = new StringBuilder("{\"challenge\":\"").append(challengeHex).append("\",\"strongbox_requested\":")
                .append(strongbox).append(",\"pop_sig\":\"").append(android.util.Base64.encodeToString(pop, android.util.Base64.NO_WRAP))
                .append("\",\"chain\":[");
        for (int i = 0; i < chain.length; i++) {
            if (i > 0) j.append(',');
            j.append('"').append(android.util.Base64.encodeToString(chain[i].getEncoded(), android.util.Base64.NO_WRAP)).append('"');
        }
        j.append("]}");
        write("attest.json", j.toString());
        ks.deleteEntry(alias);
        status("attest ok chain=" + chain.length + " strongbox=" + strongbox);
    }

    // ------------------------------------------------------- v18: auth-bound keys
    static byte[] hex(String s) {
        if (s == null || s.length() % 2 != 0) throw new IllegalArgumentException("challenge hex required");
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static org.json.JSONObject exc(org.json.JSONObject o, String prefix, Throwable e) throws org.json.JSONException {
        o.put(prefix + "exception", e.getClass().getName()).put(prefix + "message", String.valueOf(e.getMessage()));
        if (e.getCause() != null) o.put(prefix + "cause", e.getCause().getClass().getName() + ": " + e.getCause().getMessage());
        return o;
    }

    /** What the keystore itself says about the key (the source of truth for the auth binding). */
    static org.json.JSONObject keyInfo(java.security.PrivateKey k) {
        org.json.JSONObject o = new org.json.JSONObject();
        try {
            android.security.keystore.KeyInfo ki = java.security.KeyFactory.getInstance(k.getAlgorithm(), "AndroidKeyStore")
                    .getKeySpec(k, android.security.keystore.KeyInfo.class);
            o.put("userAuthRequired", ki.isUserAuthenticationRequired())
             .put("userAuthType", ki.getUserAuthenticationType())
             .put("userAuthTimeoutS", ki.getUserAuthenticationValidityDurationSeconds())
             .put("userAuthEnforcedBySecureHw", ki.isUserAuthenticationRequirementEnforcedBySecureHardware())
             .put("invalidatedByBiometricEnrollment", ki.isInvalidatedByBiometricEnrollment())
             .put("insideSecureHardware", ki.isInsideSecureHardware());
            if (android.os.Build.VERSION.SDK_INT >= 31) o.put("securityLevel", ki.getSecurityLevel());
        } catch (Exception e) {
            try { exc(o, "", e); } catch (org.json.JSONException ignored) { }
        }
        return o;
    }

    /** attest with any of the v18 extras: auth=none|strong|any, timeout (s, 0 = per use), invalidate,
     *  unlocked, alias (key is KEPT under that alias for sign/sign_prompt). Writes attest.json. */
    void attestBound(Intent it) throws Exception {
        String challengeHex = it.getStringExtra("challenge");
        boolean strongbox = it.getBooleanExtra("strongbox", false);
        String auth = it.getStringExtra("auth") == null ? "none" : it.getStringExtra("auth");
        int timeout = it.getIntExtra("timeout", 0);
        String keepAlias = it.getStringExtra("alias");
        org.json.JSONObject params = new org.json.JSONObject().put("auth", auth).put("timeout", timeout)
                .put("invalidate", it.hasExtra("invalidate") ? (Object) it.getBooleanExtra("invalidate", true) : org.json.JSONObject.NULL)
                .put("unlocked", it.hasExtra("unlocked") ? (Object) it.getBooleanExtra("unlocked", false) : org.json.JSONObject.NULL)
                .put("alias", keepAlias == null ? org.json.JSONObject.NULL : keepAlias)
                .put("strongbox", strongbox).put("key_kept", keepAlias != null);
        org.json.JSONObject j = new org.json.JSONObject().put("challenge", challengeHex)
                .put("strongbox_requested", strongbox).put("params", params).put("ok", false);
        String alias = keepAlias != null ? keepAlias : "probe-attest-" + System.currentTimeMillis();
        java.security.KeyStore ks = java.security.KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        java.security.KeyPair kp;
        try {
            byte[] ch = hex(challengeHex);
            int types;
            if ("none".equals(auth)) types = 0;
            else if ("strong".equals(auth)) types = android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG;
            else if ("any".equals(auth)) types = android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG
                    | android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL;
            else throw new IllegalArgumentException("auth must be none|strong|any");
            if (timeout < 0) throw new IllegalArgumentException("timeout must be >= 0");
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance(
                    android.security.keystore.KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            android.security.keystore.KeyGenParameterSpec.Builder b = new android.security.keystore.KeyGenParameterSpec.Builder(
                    alias, android.security.keystore.KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(ch);
            if (strongbox) b.setIsStrongBoxBacked(true);
            if (types != 0) {
                b.setUserAuthenticationRequired(true);
                b.setUserAuthenticationParameters(timeout, types);
            }
            if (it.hasExtra("invalidate")) b.setInvalidatedByBiometricEnrollment(it.getBooleanExtra("invalidate", true));
            if (it.hasExtra("unlocked")) b.setUnlockedDeviceRequired(it.getBooleanExtra("unlocked", false));
            if (keepAlias != null && ks.containsAlias(alias)) { ks.deleteEntry(alias); params.put("replaced_existing", true); }
            kpg.initialize(b.build());
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            write("attest.json", exc(j, "", e).toString());
            status("attest(bound) keygen failed " + e);
            throw e;
        }
        java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
        org.json.JSONArray ca = new org.json.JSONArray();
        for (java.security.cert.Certificate c : chain)
            ca.put(android.util.Base64.encodeToString(c.getEncoded(), android.util.Base64.NO_WRAP));
        j.put("chain", ca).put("keyinfo", keyInfo(kp.getPrivate()));
        // Proof of possession: for an auth-bound key this is EXPECTED to fail without a prompt
        // (unless a time-bound key's window is still open from a recent unlock); record either way.
        try {
            java.security.Signature sg = java.security.Signature.getInstance("SHA256withECDSA");
            sg.initSign(kp.getPrivate());
            sg.update(hex(challengeHex));
            j.put("pop_sig", android.util.Base64.encodeToString(sg.sign(), android.util.Base64.NO_WRAP));
        } catch (Exception e) {
            j.put("pop_sig", org.json.JSONObject.NULL);
            exc(j, "pop_", e);
        }
        j.put("ok", true);
        write("attest.json", j.toString());
        if (keepAlias == null) ks.deleteEntry(alias);
        status("attest(bound) ok chain=" + chain.length + " params=" + params);
    }

    static java.security.PrivateKey loadKey(String alias) throws Exception {
        if (alias == null) throw new IllegalArgumentException("alias required");
        java.security.KeyStore ks = java.security.KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        java.security.Key k = ks.getKey(alias, null);
        if (!(k instanceof java.security.PrivateKey)) throw new java.security.KeyStoreException("no private key under alias " + alias);
        return (java.security.PrivateKey) k;
    }

    /** sign: Signature.initSign/sign with NO prompt. Writes sign.json. */
    void sign(String alias, String challengeHex) throws Exception {
        org.json.JSONObject j = new org.json.JSONObject().put("mode", "sign")
                .put("alias", alias == null ? org.json.JSONObject.NULL : alias).put("challenge", challengeHex).put("ok", false);
        String stage = "load";
        try {
            byte[] ch = hex(challengeHex);
            java.security.PrivateKey k = loadKey(alias);
            j.put("keyinfo", keyInfo(k));
            java.security.Signature sg = java.security.Signature.getInstance("SHA256withECDSA");
            stage = "initSign";
            sg.initSign(k);
            stage = "sign";
            sg.update(ch);
            j.put("sig", android.util.Base64.encodeToString(sg.sign(), android.util.Base64.NO_WRAP)).put("ok", true);
            stage = "done";
        } catch (Exception e) {
            exc(j, "", e);
        }
        j.put("stage", stage);
        write("sign.json", j.toString());
        status("sign ok=" + j.getBoolean("ok") + " stage=" + stage + " " + j.optString("exception"));
    }

    /** sign_prompt: BiometricPrompt (authn=strong|strong_or_credential), CryptoObject-bound when the
     *  key allows initSign before auth (per-use keys); a time-bound key that refuses initSign is
     *  signed after a plain prompt instead. Times out after 60 s. Writes sign_prompt.json either way. */
    void signPrompt(String alias, String challengeHex, String authn) throws Exception {
        final String an = authn == null ? "strong" : authn;
        org.json.JSONObject j = new org.json.JSONObject().put("mode", "sign_prompt")
                .put("alias", alias == null ? org.json.JSONObject.NULL : alias).put("challenge", challengeHex)
                .put("authn", an).put("ok", false).put("timeout", false);
        try {
            byte[] ch = hex(challengeHex);
            final int authenticators;
            if ("strong".equals(an)) authenticators = android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG;
            else if ("strong_or_credential".equals(an)) authenticators =
                    android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
                    | android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL;
            else throw new IllegalArgumentException("authn must be strong|strong_or_credential");
            j.put("can_authenticate", getSystemService(android.hardware.biometrics.BiometricManager.class).canAuthenticate(authenticators));
            final java.security.PrivateKey k = loadKey(alias);
            j.put("keyinfo", keyInfo(k));
            final java.security.Signature sg = java.security.Signature.getInstance("SHA256withECDSA");
            boolean bound;
            try { sg.initSign(k); bound = true; }
            catch (android.security.keystore.UserNotAuthenticatedException e) { bound = false; exc(j, "pre_init_", e); }
            final boolean cryptoBound = bound;
            j.put("crypto_object", cryptoBound);
            final java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
            final Object[] res = new Object[3];  // [0] AuthenticationResult, [1] error code, [2] error text
            final int[] failed = {0};
            final android.os.CancellationSignal cancel = new android.os.CancellationSignal();
            runOnUiThread(() -> {
                try {
                    android.hardware.biometrics.BiometricPrompt.Builder bb = new android.hardware.biometrics.BiometricPrompt.Builder(this)
                            .setTitle("probe: sign").setSubtitle("key " + alias).setAllowedAuthenticators(authenticators)
                            .setConfirmationRequired(false);
                    if ((authenticators & android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 0)
                        bb.setNegativeButton("Cancel", getMainExecutor(), (d, w) -> {
                            synchronized (res) { if (res[0] == null && res[1] == null) { res[1] = -2; res[2] = "negative button"; } }
                            done.countDown();
                        });
                    android.hardware.biometrics.BiometricPrompt bp = bb.build();
                    android.hardware.biometrics.BiometricPrompt.AuthenticationCallback cb =
                            new android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                        @Override public void onAuthenticationSucceeded(android.hardware.biometrics.BiometricPrompt.AuthenticationResult r) {
                            synchronized (res) { if (res[1] == null) res[0] = r; }
                            done.countDown();
                        }
                        @Override public void onAuthenticationError(int code, CharSequence msg) {
                            synchronized (res) { if (res[0] == null && res[1] == null) { res[1] = code; res[2] = String.valueOf(msg); } }
                            done.countDown();
                        }
                        @Override public void onAuthenticationFailed() { synchronized (res) { failed[0]++; } }
                    };
                    if (cryptoBound) bp.authenticate(new android.hardware.biometrics.BiometricPrompt.CryptoObject(sg), cancel, getMainExecutor(), cb);
                    else bp.authenticate(cancel, getMainExecutor(), cb);
                } catch (Throwable t) {
                    synchronized (res) { res[1] = -1; res[2] = t.getClass().getName() + ": " + t.getMessage(); }
                    done.countDown();
                }
            });
            if (!done.await(60, TimeUnit.SECONDS)) {
                j.put("timeout", true);
                runOnUiThread(cancel::cancel);
                done.await(5, TimeUnit.SECONDS);
            }
            android.hardware.biometrics.BiometricPrompt.AuthenticationResult ar;
            synchronized (res) {
                ar = (android.hardware.biometrics.BiometricPrompt.AuthenticationResult) res[0];
                j.put("failed_attempts", failed[0]);
                if (ar == null) {
                    j.put("error_code", res[1] == null ? org.json.JSONObject.NULL : res[1])
                     .put("error", res[2] == null ? (j.getBoolean("timeout") ? "timeout, no callback" : "no result") : res[2]);
                    res[1] = -3;  // a late success after we gave up must not count
                }
            }
            if (ar != null) {
                int t = ar.getAuthenticationType();
                j.put("authType", t).put("authTypeName", t == 1 ? "DEVICE_CREDENTIAL" : t == 2 ? "BIOMETRIC" : "UNKNOWN");
                java.security.Signature s2 = cryptoBound ? ar.getCryptoObject().getSignature() : sg;
                if (!cryptoBound) s2.initSign(k);
                s2.update(ch);
                j.put("sig", android.util.Base64.encodeToString(s2.sign(), android.util.Base64.NO_WRAP)).put("ok", true);
            }
        } catch (Exception e) {
            exc(j, "", e);
        }
        write("sign_prompt.json", j.toString());
        status("sign_prompt ok=" + j.getBoolean("ok") + " timeout=" + j.getBoolean("timeout") + " " + j.optString("exception") + j.optString("error"));
    }

    // ------------------------------------------------------------- v19: capture
    // JSON-lines sensor capture (schema probe.capture/1). The sensor callback only copies the event
    // into a bounded queue (offer, never blocks; a full queue counts a drop); a writer thread formats
    // and writes. Screen: the activity's FLAG_KEEP_SCREEN_ON (set in onCreate for every mode) is held
    // for exactly the capture, because the activity finishes only when this method returns. Chosen over
    // a wakelock: no new permission (WAKE_LOCK is not declared), released by the window manager if the
    // activity dies (no leak), and - the deciding point - since Android 9 an app that is not in the
    // foreground gets no continuous-sensor events, so a PARTIAL wakelock would keep the CPU awake but
    // still lose the data. The flag does not turn the screen on or survive the power button; each
    // confound line records screen_on so a capture with the screen off is visible, not silent.
    static final int[] CAPTURE_DEFAULT_TYPES = {1, 2, 4, 5, 8, 9, 10, 11, 14, 15, 16, 35};
    static final int CAPTURE_QUEUE = 1 << 16;
    static final int CAPTURE_MAX_S = 600;
    volatile boolean capturing;

    /** One queued record. kind 0 = sensor event, 1 = accuracy change, 2 = preformatted line, 3 = end. */
    static final class Rec {
        final int kind, type, acc; final long ts; final float[] v; final String line;
        Rec(int kind, int type, long ts, float[] v, int acc, String line) {
            this.kind = kind; this.type = type; this.ts = ts; this.v = v; this.acc = acc; this.line = line;
        }
    }

    static int intExtra(Intent it, String k, int def) {
        Object o = it.getExtras() == null ? null : it.getExtras().get(k);
        if (o == null) return def;
        if (o instanceof Number) return ((Number) o).intValue();
        return Integer.parseInt(o.toString().trim());   // `-e dur 60` works as well as `--ei dur 60`
    }

    static String jf(float f) { return Float.isNaN(f) || Float.isInfinite(f) ? "null" : Float.toString(f); }

    static boolean captureable(Sensor s) {
        int rm = s.getReportingMode();
        return !s.isWakeUpSensor() && rm != Sensor.REPORTING_MODE_ONE_SHOT && rm != Sensor.REPORTING_MODE_SPECIAL_TRIGGER;
    }

    void capture(Intent it) throws Exception {
        if (capturing) throw new IllegalStateException("capture already running");
        int dur = intExtra(it, "dur", 60);
        if (dur < 1 || dur > CAPTURE_MAX_S) throw new IllegalArgumentException("dur must be 1.." + CAPTURE_MAX_S + " s, got " + dur);
        String rate = it.getStringExtra("rate");
        if (rate == null) rate = "fastest";
        final int delay;
        switch (rate) {
            case "fastest": delay = SensorManager.SENSOR_DELAY_FASTEST; break;
            case "game": delay = SensorManager.SENSOR_DELAY_GAME; break;
            case "ui": delay = SensorManager.SENSOR_DELAY_UI; break;
            default: throw new IllegalArgumentException("rate must be fastest|game|ui, got " + rate);
        }
        String name = it.getStringExtra("out");
        if (name == null) name = "capture_" + System.currentTimeMillis() + ".jsonl";
        if (!name.matches("[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")) throw new IllegalArgumentException("bad out name " + name);

        SensorManager sm = getSystemService(SensorManager.class);
        ArrayList<Integer> types = new ArrayList<>();
        String typesArg = it.getStringExtra("types");
        boolean defaultTypes = typesArg == null || typesArg.trim().isEmpty();
        if (defaultTypes) {
            for (int t : CAPTURE_DEFAULT_TYPES) types.add(t);
            for (Sensor s : sm.getSensorList(Sensor.TYPE_ALL))
                if (s.getType() >= Sensor.TYPE_DEVICE_PRIVATE_BASE && captureable(s) && !types.contains(s.getType()))
                    types.add(s.getType());
        } else {
            for (String x : typesArg.split(",")) {
                int t = Integer.parseInt(x.trim());
                if (!types.contains(t)) types.add(t);
            }
        }
        // One sensor per type (events carry only the type): the default sensor if it qualifies,
        // else the first non-wakeup, non-one-shot sensor of that type.
        LinkedHashMap<Integer, Sensor> pick = new LinkedHashMap<>();
        StringBuilder skipped = new StringBuilder();
        for (int t : types) {
            Sensor chosen = sm.getDefaultSensor(t);
            if (chosen == null || !captureable(chosen)) {
                chosen = null;
                for (Sensor s : sm.getSensorList(t)) if (s.getType() == t && captureable(s)) { chosen = s; break; }
            }
            if (chosen == null) {
                boolean any = !sm.getSensorList(t).isEmpty();
                skipped.append(skipped.length() == 0 ? "" : ",").append("{\"type\":").append(t)
                       .append(",\"reason\":").append(q(any ? "only wakeup/one-shot/trigger sensors" : "absent")).append('}');
            } else pick.put(t, chosen);
        }

        final ArrayBlockingQueue<Rec> queue = new ArrayBlockingQueue<>(CAPTURE_QUEUE);
        final AtomicLong dropped = new AtomicLong();
        final Map<Integer, long[]> dropByType = new java.util.concurrent.ConcurrentHashMap<>();
        for (int t : pick.keySet()) dropByType.put(t, new long[1]);
        SensorEventListener l = new SensorEventListener() {
            @Override public void onSensorChanged(SensorEvent e) {
                // SensorEvent objects are reused by the framework: copy the values before queueing.
                int t = e.sensor.getType();
                if (!queue.offer(new Rec(0, t, e.timestamp, e.values.clone(), e.accuracy, null))) {
                    dropped.incrementAndGet();
                    long[] d = dropByType.get(t);
                    if (d != null) d[0]++;   // only the single sensor thread writes this
                }
            }
            @Override public void onAccuracyChanged(Sensor s, int a) {
                if (!queue.offer(new Rec(1, s.getType(), SystemClock.elapsedRealtimeNanos(), null, a, null)))
                    dropped.incrementAndGet();
            }
        };
        HandlerThread st = new HandlerThread("probe-capture");
        st.start();
        Handler sh = new Handler(st.getLooper());

        capturing = true;
        File f = new File(out, name);
        final BufferedWriter w = new BufferedWriter(new FileWriter(f), 1 << 20);
        final long[] counts = new long[1];
        final IOException[] writeErr = new IOException[1];
        final Map<Integer, long[]> perType = new LinkedHashMap<>();
        Thread writer = null;
        try {
            long startEl = SystemClock.elapsedRealtimeNanos();
            long startWall = System.currentTimeMillis();
            StringBuilder sens = new StringBuilder();
            StringBuilder regFail = new StringBuilder();
            for (Map.Entry<Integer, Sensor> en : pick.entrySet()) {
                Sensor s = en.getValue();
                if (sm.registerListener(l, s, delay, 0, sh)) {
                    perType.put(en.getKey(), new long[1]);
                    sens.append(sens.length() == 0 ? "" : ",")
                        .append("{\"type\":").append(s.getType())
                        .append(",\"name\":").append(q(s.getName()))
                        .append(",\"vendor\":").append(q(s.getVendor()))
                        .append(",\"version\":").append(s.getVersion())
                        .append(",\"resolution\":").append(jf(s.getResolution()))
                        .append(",\"maxRange\":").append(jf(s.getMaximumRange()))
                        .append(",\"minDelay_us\":").append(s.getMinDelay())
                        .append(",\"power_mA\":").append(jf(s.getPower()))
                        .append(",\"reportingMode\":").append(s.getReportingMode())
                        .append(",\"fifoMax\":").append(s.getFifoMaxEventCount())
                        .append('}');
                } else {
                    regFail.append(regFail.length() == 0 ? "" : ",").append(s.getType());
                    status("capture register FAILED " + s.getName());
                }
            }
            StringBuilder hdr = new StringBuilder(1024);
            hdr.append("{\"schema\":\"probe.capture/1\"")
               .append(",\"model\":").append(q(android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL))
               .append(",\"sdk\":").append(android.os.Build.VERSION.SDK_INT)
               .append(",\"app_version\":19")
               .append(",\"started_elapsed_ns\":").append(startEl)
               .append(",\"started_wall_ms\":").append(startWall)
               .append(",\"rate\":").append(q(rate))
               .append(",\"rate_delay_constant\":").append(delay)
               .append(",\"max_report_latency_us\":0")
               .append(",\"dur_s\":").append(dur)
               .append(",\"types_requested\":").append(q(defaultTypes ? "default" : typesArg))
               .append(",\"queue_capacity\":").append(CAPTURE_QUEUE)
               .append(",\"sensors\":[").append(sens).append(']')
               .append(",\"skipped\":[").append(skipped).append(']')
               .append(",\"register_failed\":[").append(regFail).append(']')
               .append("}\n");
            w.write(hdr.toString());

            writer = new Thread(() -> {
                StringBuilder sb = new StringBuilder(160);
                while (true) {
                    Rec r;
                    try { r = queue.take(); } catch (InterruptedException ie) { break; }
                    if (r.kind == 3) {
                        try { w.write(r.line); w.flush(); } catch (IOException ioe) { if (writeErr[0] == null) writeErr[0] = ioe; }
                        break;
                    }
                    sb.setLength(0);
                    if (r.kind == 0) {
                        sb.append("{\"t\":").append(r.type).append(",\"ts\":").append(r.ts).append(",\"v\":[");
                        for (int i = 0; i < r.v.length; i++) sb.append(i == 0 ? "" : ",").append(jf(r.v[i]));
                        sb.append("],\"a\":").append(r.acc).append("}\n");
                        long[] c = perType.get(r.type);
                        if (c != null) c[0]++;
                        counts[0]++;
                    } else if (r.kind == 1) {
                        sb.append("{\"acc\":{\"t\":").append(r.type).append(",\"a\":").append(r.acc)
                          .append(",\"ts\":").append(r.ts).append("}}\n");
                    } else {
                        sb.append(r.line);
                    }
                    try {
                        w.write(sb.toString());
                        if (r.kind == 2) w.flush();   // confound lines (1 Hz): a crash keeps all but the last second
                    } catch (IOException ioe) { if (writeErr[0] == null) writeErr[0] = ioe; }
                }
            }, "probe-capture-writer");
            writer.start();
            status("capture " + name + " rate=" + rate + " dur=" + dur + " sensors=" + perType.keySet()
                    + (regFail.length() > 0 ? " register_failed=" + regFail : ""));

            PowerManager pm = getSystemService(PowerManager.class);
            long confoundDropped = 0;
            long endEl = startEl + dur * 1_000_000_000L;
            for (int i = 0; ; i++) {
                long nowEl = SystemClock.elapsedRealtimeNanos();
                if (nowEl >= endEl) break;
                Intent bat = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
                int temp = bat == null ? Integer.MIN_VALUE : bat.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Integer.MIN_VALUE);
                int lvl = bat == null ? -1 : bat.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                int scale = bat == null ? -1 : bat.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
                int plugged = bat == null ? -1 : bat.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
                String c = "{\"c\":{\"batt_temp_c\":" + (temp == Integer.MIN_VALUE ? "null" : String.valueOf(temp / 10.0))
                        + ",\"batt_level\":" + (lvl >= 0 && scale > 0 ? String.valueOf(lvl * 100.0 / scale) : "null")
                        + ",\"plugged\":" + plugged
                        + ",\"screen_on\":" + pm.isInteractive()
                        + ",\"thermal_status\":" + pm.getCurrentThermalStatus()
                        + ",\"dropped_so_far\":" + dropped.get()
                        + ",\"elapsed_ns\":" + SystemClock.elapsedRealtimeNanos()
                        + ",\"wall_ms\":" + System.currentTimeMillis() + "}}\n";
                if (!queue.offer(new Rec(2, 0, 0, null, 0, c), 2, TimeUnit.SECONDS)) confoundDropped++;
                if (i % 10 == 9) status("capture events " + counts[0] + " dropped " + dropped.get());
                long next = startEl + (i + 1) * 1_000_000_000L;
                long sleepMs = (Math.min(next, endEl) - SystemClock.elapsedRealtimeNanos()) / 1_000_000L;
                if (sleepMs > 0) Thread.sleep(sleepMs);
            }
            long stopEl = SystemClock.elapsedRealtimeNanos();
            long stopWall = System.currentTimeMillis();
            sm.unregisterListener(l);
            st.quitSafely();
            st.join(3000);   // after this no callback can run: drop counters are final
            final long dr = dropped.get();
            final long cdr = confoundDropped;
            final StringBuilder dbt = new StringBuilder();
            for (Map.Entry<Integer, long[]> en : dropByType.entrySet())
                if (en.getValue()[0] > 0) dbt.append(dbt.length() == 0 ? "" : ",").append('"').append(en.getKey()).append("\":").append(en.getValue()[0]);
            // END goes behind every queued record; once the writer has exited (join) it no longer touches
            // w/perType/counts, so the footer is written from here.
            queue.put(new Rec(3, 0, 0, null, 0, ""));
            writer.join(60_000);
            if (writer.isAlive()) throw new IOException("capture writer did not drain within 60 s");
            StringBuilder cnt = new StringBuilder();
            for (Map.Entry<Integer, long[]> en : perType.entrySet())
                cnt.append(cnt.length() == 0 ? "" : ",").append('"').append(en.getKey()).append("\":").append(en.getValue()[0]);
            String footer = "{\"end\":{\"elapsed_ns\":" + stopEl + ",\"wall_ms\":" + stopWall
                    + ",\"counts\":{" + cnt + "},\"total\":" + counts[0] + ",\"dropped\":" + dr
                    + ",\"dropped_by_type\":{" + dbt + "},\"confound_dropped\":" + cdr
                    + ",\"write_error\":" + (writeErr[0] == null ? "null" : q(String.valueOf(writeErr[0]))) + "}}\n";
            w.write(footer);
            w.flush();
            status("capture done file=" + name + " events=" + counts[0] + " dropped=" + dr
                    + (writeErr[0] == null ? "" : " WRITE_ERROR " + writeErr[0]));
            if (writeErr[0] != null) throw writeErr[0];
        } finally {
            sm.unregisterListener(l);
            st.quitSafely();
            if (writer != null && writer.isAlive()) writer.interrupt();
            try { w.close(); } catch (IOException ignored) { }
            capturing = false;
        }
    }

    // ------------------------------------------------------------- v19: clock
    /** n back-to-back reads of the three Android clocks -> clock.json (schema probe.clock/1).
     *  The host brackets the adb call; see phone/clock_offset.py (the ClockCli path is tighter). */
    void clock(int n) throws Exception {
        if (n < 1 || n > 10000) throw new IllegalArgumentException("n must be 1..10000, got " + n);
        long[] el = new long[n], wall = new long[n], up = new long[n];
        for (int i = 0; i < n; i++) {
            el[i] = SystemClock.elapsedRealtimeNanos();
            wall[i] = System.currentTimeMillis();
            up[i] = SystemClock.uptimeMillis();
        }
        StringBuilder sb = new StringBuilder(64 * n + 128);
        sb.append("{\"schema\":\"probe.clock/1\",\"model\":").append(q(android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL))
          .append(",\"sdk\":").append(android.os.Build.VERSION.SDK_INT).append(",\"n\":").append(n).append(",\"samples\":[");
        for (int i = 0; i < n; i++)
            sb.append(i == 0 ? "" : ",").append("{\"elapsed_ns\":").append(el[i]).append(",\"wall_ms\":").append(wall[i])
              .append(",\"uptime_ms\":").append(up[i]).append('}');
        sb.append("]}\n");
        write("clock.json", sb.toString());
        status("clock n=" + n + " elapsed_ns=" + el[0]);
    }
}
