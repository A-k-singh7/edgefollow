# The probe app

The Android app the phone runs used: it posts the phone's radio, Wi-Fi, motion, environment and location records
into its AE on the oneM2M CSE, and the drivers start its modes with `am start -e mode <mode>` (the list is at the top
of `Main.java`).

- **Source here: version 20** (`AndroidManifest.xml`, versionCode 20; `V20_NOTES.md`). It was installed on both lab
  phones on 2026-11-19, after the sitting of that day; no published record comes from version 20.
- **The published phone records come from version 19.** Both phones ran version 19 in the sitting of 2026-11-19
  (`phone/SITTING_B_2026-11-19_SUMMARY.md`), which made the records in `records/sitting_b/`. `V19_NOTES.md` is
  that version's history.
- The published copy of this folder leaves out one mode of `Main.java` that only other work uses.

## Build

    bash build_v20.sh

It needs the Android SDK build-tools 36.0.0 and platform android-35 at the paths written in the script, a JDK
(`javac`, source and target 11) and a debug keystore at `~/.android/debug.keystore`, which signs the APK. Output:
`build_v20/probe.apk` (not tracked). The script writes only into `build_v20/` and refuses to run if
`build_v20/probe.apk` exists. `build.sh` is the build of version 19: it stamps version code 19 on the same source.
