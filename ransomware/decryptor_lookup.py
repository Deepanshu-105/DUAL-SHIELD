import argparse, json, os, re

KNOWN_DECRYPTABLE = {
    "wannacry": {
        "match_ext": [".wncry", ".wcry"],
        "note_filename": "@Please_Read_Me@.txt",
        "decryptor": "WanaKiwi (works only if the machine was never rebooted "
                      "after infection; exploits a key left in memory)",
        "source": "https://www.nomoreransom.org",
    },
    "stop_djvu_offline": {
        "match_ext": [".stop", ".djvu"],
        "note_filename": "_readme.txt",
        "decryptor": "Emsisoft STOP Djvu Decryptor (offline-key variants only — "
                      "online-key variants of the same family are NOT recoverable)",
        "source": "https://www.nomoreransom.org",
    },
    "teslacrypt": {
        "match_ext": [".ecc", ".ezz", ".exx"],
        "note_filename": "Howto_RESTORE_FILES.txt",
        "decryptor": "TeslaDecoder (TeslaCrypt's own developers published the "
                      "master key when they shut the operation down)",
        "source": "https://www.nomoreransom.org",
    },
}


def identify(folder):
    exts = set()
    note_names = set()
    for root, _, files in os.walk(folder):
        for name in files:
            ext = os.path.splitext(name)[1]
            if ext:
                exts.add(ext)
            if re.search(r"readme|restore|decrypt|howto", name, re.I):
                note_names.add(name)

    matches = []
    for family, info in KNOWN_DECRYPTABLE.items():
        if any(e in exts for e in info["match_ext"]) or info["note_filename"] in note_names:
            matches.append((family, info))
    return matches, exts, note_names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    a = ap.parse_args()

    matches, exts, notes = identify(a.folder)
    print("Observed extensions:", sorted(exts) or "(none)")
    print("Observed note-like filenames:", sorted(notes) or "(none)")
    print()

    if not matches:
        print("NO_KNOWN_DECRYPTOR")
        print("Most current ransomware (correctly implemented AES) has NO public decryptor.")
        print("Fall back to: vault.py restore, or shadow_recovery.py.")
        return 1

    for family, info in matches:
        print("POSSIBLE_MATCH family=%s" % family)
        print("  decryptor:", info["decryptor"])
        print("  source:   ", info["source"])
    return 0


if __name__ == "__main__":
    exit(main())
