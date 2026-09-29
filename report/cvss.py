# -*- coding: utf-8 -*-
"""Kalkulator CVSS v3.1 (spesifikasi FIRST) - untuk reproduktibilitas skor."""

import math

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

AV_TXT = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
AC_TXT = {"L": "Low", "H": "High"}
PR_TXT = {"N": "None", "L": "Low", "H": "High"}
UI_TXT = {"N": "None", "R": "Required"}
CIA_TXT = {"H": "High", "L": "Low", "N": "None"}


def roundup1(x):
    """CVSS v3.1 Roundup: ke atas ke 1 desimal."""
    return math.ceil(x * 10) / 10.0


def cvss31(vector):
    p = dict(kv.split(":") for kv in vector.split("/")[1:])
    sc = p["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if sc else 0.62, "H": 0.50 if sc else 0.27}[p["PR"]]

    iss = 1 - ((1 - CIA[p["C"]]) * (1 - CIA[p["I"]]) * (1 - CIA[p["A"]]))
    if sc:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploit = 8.22 * AV[p["AV"]] * AC[p["AC"]] * pr * UI[p["UI"]]

    if impact <= 0:
        score = 0.0
    elif sc:
        score = roundup1(min(1.08 * (impact + exploit), 10))
    else:
        score = roundup1(min(impact + exploit, 10))

    return {
        "vector": vector,
        "score": score,
        "iss": iss,
        "impact": impact,
        "exploit": exploit,
        "pr_val": pr,
        "scope_changed": sc,
        "m": {
            "AV": AV_TXT[p["AV"]], "AC": AC_TXT[p["AC"]], "PR": PR_TXT[p["PR"]],
            "UI": UI_TXT[p["UI"]], "S": "Changed" if sc else "Unchanged",
            "C": CIA_TXT[p["C"]], "I": CIA_TXT[p["I"]], "A": CIA_TXT[p["A"]],
        },
        "mraw": p,
    }


def severity(score):
    if score == 0:
        return "None"
    if score <= 3.9:
        return "LOW"
    if score <= 6.9:
        return "MEDIUM"
    if score <= 8.9:
        return "HIGH"
    return "CRITICAL"


def qualitative_vector(vector):
    """Vektor tekstual per CVSS v3.1 Appendix A (CVSS:3.1/AV:N/AC:L/...)."""
    p = dict(kv.split(":") for kv in vector.split("/")[1:])
    return "CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s" % (
        p["AV"], p["AC"], p["PR"], p["UI"], p["S"], p["C"], p["I"], p["A"])
