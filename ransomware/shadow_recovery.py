import argparse, os, re, shutil, subprocess, sys


def list_shadows():
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_ShadowCopy | Select-Object ID,InstallDate,DeviceObject | Format-List"],
        capture_output=True, text=True)
    print(r.stdout or "NO_SHADOW_COPIES (none exist, or not run as Administrator)")
    return r.stdout


def _parse_device_objects(raw):
    return re.findall(r"DeviceObject\s*:\s*(\S+)", raw)


def recover(folder, out_dir):
    raw = list_shadows()
    devices = _parse_device_objects(raw)
    if not devices:
        print("RECOVER_FAIL no shadow copies available on this host")
        return False

    drive, rel = os.path.splitdrive(os.path.abspath(folder))
    rel = rel.lstrip("\\/")
    os.makedirs(out_dir, exist_ok=True)
    found_any = False

    for i, dev in enumerate(devices):
        shadow_path = os.path.join(dev + "\\", rel)
        if os.path.isdir(shadow_path):
            dest = os.path.join(out_dir, "shadow_%d" % i)
            shutil.copytree(shadow_path, dest, dirs_exist_ok=True)
            n = sum(len(f) for _, _, f in os.walk(dest))
            print("RECOVERED shadow_%d -> %s, %d files" % (i, dest, n))
            found_any = True

    if not found_any:
        print("RECOVER_FAIL folder not found in any shadow copy")
    return found_any


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["list", "recover"])
    ap.add_argument("folder", nargs="?")
    ap.add_argument("--out", default="recovered_from_shadow")
    a = ap.parse_args()
    if a.cmd == "list":
        list_shadows()
    else:
        sys.exit(0 if recover(a.folder, a.out) else 1)
