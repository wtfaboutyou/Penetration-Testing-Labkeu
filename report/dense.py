# -*- coding: utf-8 -*-
"""Render temuan dalam format padat: satu blok per temuan, tanpa sub-bagian,
tanpa blok kode terpisah. Mengikuti format laporan ringkas (satu butir
bukti = perintah -> hasil dalam satu baris) agar jumlah halaman tetap rendah
walaupun isinya tetap dapat ditelusuri.
"""
import re

import cvss
import dx
import evidence as EV
from docx.enum.text import WD_ALIGN_PARAGRAPH

from dx import ACCENT, GREY

JUS = WD_ALIGN_PARAGRAPH.JUSTIFY

# Batas panjang agar tiap baris tetap muat tanpa memotong makna.
CMD_MAX = 120
OUT_MAX = 110
TXT_MAX = 190


def _first_line(v, limit):
    """Baris pertama yang informatif; terima str maupun list of str."""
    if not v:
        return ""
    if isinstance(v, (list, tuple)):
        parts = [str(x) for x in v]
    else:
        parts = str(v).splitlines()
    for ln in parts:
        ln = ln.strip()
        if not ln or set(ln) <= set("=-# "):
            continue
        if len(ln) > limit:
            return ln[:limit].rsplit(" ", 1)[0] + " …"
        return ln
    return ""


def _clean(s):
    return re.sub(r"\s+", " ", (s or "").strip())


def _stop(s):
    """Normalisasi akhir kalimat: satu titik, tidak dobel."""
    s = (s or "").strip().rstrip(".")
    return (s + ".") if s else ""


def _first_sentence(s, limit=TXT_MAX):
    """Potong di batas kalimat pertama yang masih utuh."""
    s = _clean(s)
    if len(s) <= limit:
        return s
    cut = s[:limit]
    for sep in (". ", "; "):
        i = cut.rfind(sep)
        if i > limit * 0.45:
            return cut[:i + 1].strip()
    return cut.rsplit(" ", 1)[0] + " …"


def _prose_blocks(field):
    """Blok pada field yang berupa prosa (bukan kode)."""
    if not field:
        return []
    if isinstance(field, str):
        return [p for p in field.split("\n\n") if p.strip()]
    out = []
    for b in field:
        if isinstance(b, str) and "\n" not in b and len(b) < 400:
            out.append(b)
    return out


def _impact_line(imp):
    """Gabungkan 2 dampak pertama jadi satu kalimat ringkas."""
    if not imp:
        return ""
    parts = []
    for it in imp[:2]:
        t = _clean(it[0] if isinstance(it, (list, tuple)) else it)
        parts.append(t)
    return " — ".join(parts).rstrip(".")


def _remediation_line(rem):
    """Ambil 2 rekomendasi pertama yang berupa teks (bukan blok kode)."""
    parts = []
    for it in rem:
        if isinstance(it, tuple):
            continue
        parts.append(_clean(it))
        if len(parts) == 2:
            break
    return " ".join(parts)


def _evidence_bullets(f):
    """Satu baris per bukti: judul, perintah kunci, dan hasil nyata."""
    ev = f.get("evidence")
    if not ev:
        return []
    rows = []
    for item in ev:
        if len(item) == 2:
            cap, cmds = item[0], item[1]
            out = ""
        else:
            cap, cmds, out = item[0], item[1], item[2]
        cap = _clean(cap)
        # Buang label "Bukti N -" yang sudah tidak perlu karena ada penomoran.
        cap = re.sub(r"^Bukti\s+\d+\s*[-–]\s*", "", cap)
        cmd = _first_line(cmds, CMD_MAX)
        o = _first_line(out, OUT_MAX)
        rows.append((cap, cmd, o))
    return rows


def render_finding(doc, f, idx=None, total=None):
    """Satu temuan dalam format padat."""
    r = cvss.cvss31(f["vector"])
    sev = cvss.severity(r["score"])
    fid = f["id"]

    # Pita ringkas: ID, judul, skor. Bukan tabel penuh.
    dx.P(doc, "%s · %s" % (fid, f["title_id"]), bold=True, size=12, space_after=1)
    dx.R(doc, [("%s" % sev.upper(), {"b": True, "sz": 9.5,
                                    "c": dx.SEV_COLOR.get(sev, ACCENT)}),
               ("   ·   CVSS v3.1 %.1f   ·   " % r["score"], {"sz": 9, "c": GREY}),
               (f["vector"], {"sz": 8, "c": GREY})], space_after=5)

    # Kelas dan endpoint
    cwe = f.get("cwe", "")
    if isinstance(cwe, (list, tuple)):
        cwe = " · ".join(str(x) for x in cwe)
    meta_bits = []
    if cwe:
        meta_bits.append(str(cwe))
    for key in ("endpoint", "component"):
        v = f.get(key)
        if v:
            meta_bits.append(_clean(str(v)))
    if meta_bits:
        dx.P(doc, "   ".join(meta_bits[:3]), size=9, color=GREY, space_after=4)

    # Akar masalah: satu kalimat dari blok prosa pertama.
    prose = _prose_blocks(f.get("root_cause"))
    if prose:
        dx.R(doc, [("Akar. ", {"b": True, "c": ACCENT}),
                   (_first_sentence(prose[0]), {})], align=JUS, space_after=4)

    # Bukti: satu baris per bukti.
    bullets = _evidence_bullets(f)
    if bullets:
        dx.R(doc, [("Bukti. ", {"b": True, "c": ACCENT})], space_after=1)
        for n, (cap, cmd, o) in enumerate(bullets, 1):
            parts = [("%d) " % n, {"b": True}), (cap, {})]
            if cmd:
                parts += [("  ", {}), (cmd, {"mono": True, "sz": 8})]
            if o:
                parts += [("  →  ", {"c": GREY, "sz": 8}), (o, {"mono": True, "sz": 8})]
            dx.R(doc, parts, align=JUS, space_after=2)
        dx.tiny_par(doc, 2)

    # Dampak
    imp = _impact_line(f.get("impact"))
    if imp:
        dx.R(doc, [("Dampak. ", {"b": True, "c": ACCENT}), (imp + ".", {})],
             align=JUS, space_after=4)

    # Remediasi
    rem = _remediation_line(f.get("remediation"))
    if rem:
        dx.R(doc, [("Remediasi. ", {"b": True, "c": ACCENT}), (rem, {})],
             align=JUS, space_after=4)

    # Verifikasi perbaikan: satu kalimat.
    v = f.get("verification")
    if isinstance(v, str):
        dx.R(doc, [("Verifikasi. ", {"b": True, "c": ACCENT}),
                   (_first_sentence(v, 170), {})], align=JUS, space_after=4)
    elif isinstance(v, list) and v:
        dx.R(doc, [("Verifikasi. ", {"b": True, "c": ACCENT}),
                   (_first_sentence(_clean(v[0]), 170), {})], align=JUS, space_after=4)

    # Status bukti: satu baris, selalu ada.
    if fid in EV.FINDING_EVIDENCE:
        st, shots, note = EV.FINDING_EVIDENCE[fid]
        colmap = {EV.TERBUKTI: dx.GREEN, EV.SEBAGIAN: dx.AMBER,
                  EV.TIDAK_LANGSUNG: dx.AMBER, EV.BELUM: dx.RED}
        label = {EV.TERBUKTI: "TERBUKTI", EV.SEBAGIAN: "SEBAGIAN",
                 EV.TIDAK_LANGSUNG: "TIDAK LANGSUNG", EV.BELUM: "BELUM DIVERIFIKASI"}[st]
        ref = ", ".join(shots) if shots else "tanpa berkas bukti"
        dx.R(doc, [("Status bukti. ", {"b": True, "c": ACCENT}),
                   (label, {"b": True, "c": colmap[st], "sz": 8.5}),
                   ("  (%s)  " % ref, {"c": GREY, "sz": 8}),
                   (_first_sentence(note, 200), {"i": True, "sz": 8, "c": GREY})],
             align=JUS, space_after=6)
    dx.tiny_par(doc, 6)


def summary_row(f):
    """Satu baris tabel untuk temuan ringkas."""
    r = cvss.cvss31(f["vector"])
    sev = cvss.severity(r["score"])
    fid = f["id"]
    cwe = f.get("cwe", "")
    if isinstance(cwe, (list, tuple)):
        cwe = " · ".join(str(x) for x in cwe)
    cwe = str(cwe).split("·")[0].strip() if cwe else "—"

    st = "—"
    stcol = None
    if fid in EV.FINDING_EVIDENCE:
        s, _shots, _n = EV.FINDING_EVIDENCE[fid]
        st = {EV.TERBUKTI: "TERBUKTI", EV.SEBAGIAN: "SEBAGIAN",
              EV.TIDAK_LANGSUNG: "TIDAK LANGSUNG", EV.BELUM: "BELUM DIVERIFIKASI"}[s]
        stcol = {EV.TERBUKTI: dx.GREEN, EV.SEBAGIAN: dx.AMBER,
                 EV.TIDAK_LANGSUNG: dx.AMBER, EV.BELUM: dx.RED}[s]

    return (fid, _clean(f["title_id"]), sev, "%.1f" % r["score"], cwe,
            _first_sentence(_impact_line(f.get("impact")) or "-", 150),
            _first_sentence(_remediation_line(f.get("remediation")) or "-", 150),
            st, stcol)


def _cwe_code(f):
    """Kode CWE saja (mis. CWE-862), tanpa deskripsi English yang panjang."""
    c = f.get("cwe", "")
    if isinstance(c, (list, tuple)):
        c = " ".join(str(x) for x in c)
    m = re.search(r"CWE-\d+", str(c))
    return m.group(0) if m else "—"


def render_brief(doc, f):
    """Temuan ringkas: dampak, remediasi, dan status bukti saja."""
    r = cvss.cvss31(f["vector"])
    sev = cvss.severity(r["score"])
    fid = f["id"]

    dx.R(doc, [("%s · " % fid, {"b": True, "sz": 10.5, "c": ACCENT}),
               (_first_sentence(f["title_id"], 90), {"b": True, "sz": 10.5}),
               ("   ", {}),
               (sev.upper(), {"b": True, "sz": 8.5, "c": dx.SEV_COLOR.get(sev, ACCENT)}),
               ("  %.1f  ·  %s" % (r["score"], _cwe_code(f)), {"sz": 8, "c": GREY})],
             space_after=2)

    imp = _impact_line(f.get("impact"))
    if imp:
        dx.R(doc, [("Dampak. ", {"b": True, "sz": 8.5, "c": ACCENT}),
                   (_stop(_first_sentence(imp, 200)), {"sz": 9})], align=JUS, space_after=1)
    rem = _remediation_line(f.get("remediation"))
    if rem:
        dx.R(doc, [("Remediasi. ", {"b": True, "sz": 8.5, "c": ACCENT}),
                   (_stop(_first_sentence(rem, 200)), {"sz": 9})], align=JUS, space_after=1)

    for n, (cap, cmd, o) in enumerate(_evidence_bullets(f)[:2], 1):
        parts = [("Bukti %d. " % n, {"b": True, "sz": 8.5, "c": ACCENT}), (_stop(cap) + " ", {"sz": 9})]
        if o:
            parts += [("→ ", {"sz": 8, "c": GREY}), (o, {"mono": True, "sz": 8})]
        dx.R(doc, parts, align=JUS, space_after=1)

    if fid in EV.FINDING_EVIDENCE:
        st, shots, note = EV.FINDING_EVIDENCE[fid]
        colmap = {EV.TERBUKTI: dx.GREEN, EV.SEBAGIAN: dx.AMBER,
                  EV.TIDAK_LANGSUNG: dx.AMBER, EV.BELUM: dx.RED}
        label = {EV.TERBUKTI: "TERBUKTI", EV.SEBAGIAN: "SEBAGIAN",
                 EV.TIDAK_LANGSUNG: "TIDAK LANGSUNG", EV.BELUM: "BELUM DIVERIFIKASI"}[st]
        ref = ", ".join(shots) if shots else "tanpa berkas bukti"
        dx.R(doc, [("Status bukti. ", {"b": True, "sz": 8.5, "c": ACCENT}),
                   (label, {"b": True, "sz": 8, "c": colmap[st]}),
                   ("  (%s)  " % ref, {"sz": 7.5, "c": GREY}),
                   (_first_sentence(note, 170), {"i": True, "sz": 7.5, "c": GREY})],
             align=JUS, space_after=4)
    dx.tiny_par(doc, 4)
