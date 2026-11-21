// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ashish Kumar Singh
package org.edgefollow.probe;

import android.os.SystemClock;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;

/**
 * v19: clock reader for phone/clock_offset.py, run from adb (not an Android component):
 *   adb shell 'CLASSPATH=$(pm path org.edgefollow.probe | head -n1 | cut -d: -f2) exec app_process /system/bin org.edgefollow.probe.ClockCli'
 * For every '\n' read on stdin it prints "<SystemClock.elapsedRealtimeNanos()> <System.currentTimeMillis()>\n"
 * and flushes. The clock is read right after the newline arrives, so the host's write/read bracket
 * contains the reading. Exits on EOF. One JVM start, then one USB round trip per reading.
 */
public final class ClockCli {
    public static void main(String[] args) throws IOException {
        InputStream in = System.in;
        PrintStream o = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), false);
        for (int c; (c = in.read()) >= 0; ) {
            if (c != '\n') continue;
            long el = SystemClock.elapsedRealtimeNanos();
            long wall = System.currentTimeMillis();
            o.print(el + " " + wall + "\n");
            o.flush();
        }
    }
}
