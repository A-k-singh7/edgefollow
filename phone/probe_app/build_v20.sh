#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
# Build the probe APK (v20) from source with the Android SDK build-tools; signs with the
# standard debug keystore (the same signer as v16..v19, so `adb install -r` is an update).
# Output: build_v20/probe.apk. Unlike build.sh this script deletes nothing: it writes only
# into build_v20/ and refuses to run when build_v20/probe.apk already exists.
set -euo pipefail
cd "$(dirname "$0")"
BT=/home/edgefollow/Android/Sdk/build-tools/36.0.0
JAR=/home/edgefollow/Android/Sdk/platforms/android-35/android.jar
O=build_v20
if [ -e "$O/probe.apk" ]; then
  echo "REFUSED: $O/probe.apk already exists. Move the whole $O folder aside by hand; this script never overwrites." >&2
  exit 1
fi
if [ -e "$O" ] && [ -n "$(ls -A "$O")" ]; then
  echo "REFUSED: $O exists and is not empty (leftovers of a failed build?). Move it aside by hand." >&2
  exit 1
fi
mkdir -p "$O/classes" "$O/dex"
"$BT/aapt2" compile --dir res -o "$O/res.zip"
"$BT/aapt2" link -o "$O/base.apk" "$O/res.zip" -I "$JAR" --manifest AndroidManifest.xml --version-code 20 --version-name 20
javac -source 11 -target 11 -Xlint:-options -cp "$JAR" -d "$O/classes" src/org/edgefollow/probe/*.java
"$BT/d8" --min-api 30 --lib "$JAR" --output "$O/dex" $(find "$O/classes" -name '*.class')
cp "$O/base.apk" "$O/unsigned.apk" && (cd "$O/dex" && zip -q ../unsigned.apk classes.dex)
"$BT/zipalign" 4 "$O/unsigned.apk" "$O/aligned.apk"
"$BT/apksigner" sign --ks ~/.android/debug.keystore --ks-pass pass:android --key-pass pass:android --out "$O/probe.apk" "$O/aligned.apk"
ls -la "$O/probe.apk"
sha256sum "$O/probe.apk"
