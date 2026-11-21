#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
# The build of version 19: it stamps version code 19 (--version-code 19 below) on the source here, which is
# version 20 (AndroidManifest.xml); build_v20.sh builds version 20. Uses the Android SDK build-tools; signs with
# the standard debug keystore. Output: build/probe.apk (gitignored).
set -e
cd "$(dirname "$0")"
rm -rf build && mkdir -p build/classes build/dex
/home/edgefollow/Android/Sdk/build-tools/36.0.0/aapt2 compile --dir res -o build/res.zip
/home/edgefollow/Android/Sdk/build-tools/36.0.0/aapt2 link -o build/base.apk build/res.zip -I /home/edgefollow/Android/Sdk/platforms/android-35/android.jar --manifest AndroidManifest.xml --version-code 19 --version-name 19
javac -source 11 -target 11 -Xlint:-options -cp /home/edgefollow/Android/Sdk/platforms/android-35/android.jar -d build/classes src/org/edgefollow/probe/*.java
/home/edgefollow/Android/Sdk/build-tools/36.0.0/d8 --min-api 30 --lib /home/edgefollow/Android/Sdk/platforms/android-35/android.jar --output build/dex $(find build/classes -name '*.class')
cp build/base.apk build/unsigned.apk && (cd build/dex && zip -q ../unsigned.apk classes.dex)
/home/edgefollow/Android/Sdk/build-tools/36.0.0/zipalign -f 4 build/unsigned.apk build/aligned.apk
/home/edgefollow/Android/Sdk/build-tools/36.0.0/apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --key-pass pass:android --out build/probe.apk build/aligned.apk
ls -la build/probe.apk
