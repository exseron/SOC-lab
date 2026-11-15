"""web/ klasöründeki arayüz dosyalarını SOC_Lab.py içine gömer.

Kullanım:
    python tools/build.py          # SOC_Lab.py içindeki EMBEDDED_ASSETS bloğunu yeniler
    python tools/build.py --check  # web/ ile gömülü içerik aynı değilse 1 ile çıkar (CI)

Çıktı deterministiktir: dosyalar sabit sırayla ve sabit zaman damgasıyla
ZIP'lenir, böylece içerik değişmedikçe git diff'i boş kalır.
"""

import argparse
import base64
import io
import re
import sys
import textwrap
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
TARGET = ROOT / "SOC_Lab.py"
BLOCK = re.compile(r'(EMBEDDED_ASSETS = """\n)(.*?)(""")', re.DOTALL)
# ZIP girdilerinin sırası; SOC_Lab.py'deki CONTENT_TYPES ile aynı dosyalar.
FILES = ["index.html", "styles.css", "data.js", "exercises.js", "app.js"]
FIXED_TIMESTAMP = (2026, 11, 15, 10, 0, 0)


def read_web_files():
    files = {}
    for name in FILES:
        # Windows'ta CRLF ile kaydedilse bile gömülü içerik LF olsun.
        text = (WEB_DIR / name).read_text(encoding="utf-8").replace("\r\n", "\n")
        files[name] = text.encode("utf-8")
    return files


def build_archive(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in FILES:
            info = zipfile.ZipInfo(name, FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, files[name], compresslevel=9)
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def embedded_files(source):
    match = BLOCK.search(source)
    if not match:
        raise SystemExit("SOC_Lab.py içinde EMBEDDED_ASSETS bloğu bulunamadı.")
    payload = "".join(match.group(2).split())
    if not payload:
        return {}
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(payload))) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def main(argv=None):
    # Türkçe karakterler cp1252 gibi konsollarda çökmesin.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="web/ dosyalarını SOC_Lab.py içine gömer.")
    parser.add_argument("--check", action="store_true", help="yalnızca senkronu kontrol et")
    args = parser.parse_args(argv)

    files = read_web_files()
    source = TARGET.read_text(encoding="utf-8")

    if args.check:
        if embedded_files(source) != files:
            print("SOC_Lab.py güncel değil: `python tools/build.py` çalıştır.", file=sys.stderr)
            return 1
        print("SOC_Lab.py, web/ ile senkron.")
        return 0

    encoded = "\n".join(textwrap.wrap(build_archive(files), 92)) + "\n"
    updated = BLOCK.sub(lambda m: m.group(1) + encoded + m.group(3), source, count=1)
    TARGET.write_text(updated, encoding="utf-8", newline="\n")
    size = sum(len(data) for data in files.values())
    print(f"SOC_Lab.py güncellendi: {len(files)} dosya, {size:,} bayt arayüz içeriği.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
