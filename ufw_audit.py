#!/usr/bin/env python3
"""UFW / iptables kural seti denetçisi: sıralama performansı, çakışma ve güvenlik analizi.

Model (ilk eşleşen kazanır):
    Paket zinciri yukarıdan aşağıya gezer, ilk eşleşen kuralda durur.
    Toplam kontrol sayısı = Σ isabet_k × (k. kurala kadar değerlendirilen kural sayısı)
                           + varsayılan politikaya düşen paket × zincir uzunluğu

Sıralama önerisi:
    İki kuralın eşleşme kümeleri kesişiyorsa göreli sıraları KORUNUR. Bu kısıt altında her
    paketin ilk eşleştiği kural değişmez; yani karar (izin/ret) ve sayaçlar aynı kalır, sadece
    kontrol sayısı düşer. Problem 1|prec|Σ w_j C_j çizelgelemesidir: küçük/orta kural
    setlerinde dinamik programlama ile kesin çözülür, büyüklerde sezgisel + yerel arama.

Sadece standart kütüphane kullanır. Salt-okunur çalışır; --apply dışında hiçbir şeyi değiştirmez.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

VERSION = "1.0"

UFW_DIR = "/etc/ufw"
UFW_DEFAULTS = "/etc/default/ufw"
TELEGRAM_CONF = "/etc/ufw-telegram.conf"
STATE_DIR = "/var/lib/ufw-telegram"

# Önem dereceleri
INFO, LOW, MEDIUM, HIGH = 0, 1, 2, 3
SEV_NAME = {INFO: "BİLGİ", LOW: "DÜŞÜK", MEDIUM: "UYARI", HIGH: "KRİTİK"}
SEV_ICON = {INFO: "ℹ️", LOW: "🔹", MEDIUM: "⚠️", HIGH: "🚨"}
SEV_COLOR = {INFO: "36", LOW: "34", MEDIUM: "33", HIGH: "31;1"}

FULL_PORT = (0, 65535)
FULL_PROTO = (0, 255)
STATES = {"NEW": 0, "ESTABLISHED": 1, "RELATED": 2, "INVALID": 3, "UNTRACKED": 4}
FULL_STATE = (0, len(STATES) - 1)
PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58, "icmpv6": 58, "esp": 50, "ah": 51,
             "gre": 47, "sctp": 132, "udplite": 136, "ipv6": 41, "igmp": 2}
PROTO_NAME = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6", 50: "esp", 51: "ah", 47: "gre", 132: "sctp"}

# Dünyaya açık bırakılması riskli portlar: port -> (ad, önem)
SENSITIVE_PORTS = {
    21: ("FTP", MEDIUM), 22: ("SSH", LOW), 23: ("Telnet", HIGH), 25: ("SMTP", INFO),
    111: ("rpcbind", HIGH), 135: ("MSRPC", HIGH), 139: ("NetBIOS", HIGH), 161: ("SNMP", MEDIUM),
    389: ("LDAP", MEDIUM), 445: ("SMB", HIGH), 512: ("rexec", HIGH), 513: ("rlogin", HIGH),
    514: ("rsh", HIGH), 873: ("rsync", MEDIUM), 1433: ("MSSQL", HIGH), 1521: ("Oracle", HIGH),
    2049: ("NFS", HIGH), 2375: ("Docker API", HIGH), 2376: ("Docker API", MEDIUM),
    2379: ("etcd", HIGH), 3306: ("MySQL", HIGH), 3389: ("RDP", HIGH), 5432: ("PostgreSQL", HIGH),
    5601: ("Kibana", MEDIUM), 5900: ("VNC", HIGH), 5985: ("WinRM", HIGH), 6379: ("Redis", HIGH),
    6443: ("Kubernetes API", MEDIUM), 8086: ("InfluxDB", MEDIUM), 9200: ("Elasticsearch", HIGH),
    9300: ("Elasticsearch", HIGH), 10250: ("kubelet", HIGH), 11211: ("Memcached", HIGH),
    15672: ("RabbitMQ", MEDIUM), 27017: ("MongoDB", HIGH),
}

# Paketi sonlandırmayan hedefler
NONTERMINAL_TARGETS = {
    "LOG", "NFLOG", "ULOG", "MARK", "CONNMARK", "TOS", "DSCP", "TTL", "HL", "SET", "TCPMSS",
    "CLASSIFY", "SECMARK", "CONNSECMARK", "NOTRACK", "CT", "TRACE", "AUDIT", "CHECKSUM",
    "RATEEST", "TEE", "ECN", "TCPOPTSTRIP", "IDLETIMER", "LED", "HMARK",
}
KNOWN_MODULES = {"tcp", "udp", "multiport", "comment", "conntrack", "state"}

MIN_PACKETS_DEFAULT = 1000      # bunun altında sıralama önerisi verilmez
DP_STATE_CAP = 400_000          # kesin çözüm için durum üst sınırı
COVER_BUDGET = 20_000           # kapsama analizinde kutu üst sınırı


class BudgetExceeded(Exception):
    pass


# =====================================================================
# Kural satırı ayrıştırma (iptables-save / ufw user.rules sözdizimi)
# =====================================================================

def parse_proto(v):
    v = v.lower()
    if v in ("all", "any", "0"):
        return FULL_PROTO
    if v in PROTO_NUM:
        return (PROTO_NUM[v], PROTO_NUM[v])
    if v.isdigit() and int(v) <= 255:
        return (int(v), int(v))
    try:
        n = socket.getprotobyname(v)
        return (n, n)
    except OSError:
        return None


def parse_ports(v):
    """'22' | '1000:2000' | '80,443,8000:8100' -> [(lo, hi), ...] ya da None (ayrıştırılamadı)."""
    out = []
    for part in v.split(","):
        part = part.strip()
        m = re.fullmatch(r"(\d*)[:\-]?(\d*)", part) if (":" in part or "-" in part) else None
        try:
            if m:
                lo = int(m.group(1)) if m.group(1) else 0
                hi = int(m.group(2)) if m.group(2) else 65535
            else:
                lo = hi = int(part)
        except ValueError:
            return None
        if not (0 <= lo <= hi <= 65535):
            return None
        out.append((lo, hi))
    return out or None


def parse_states(v):
    idx = []
    for s in v.split(","):
        s = s.strip().upper()
        if s not in STATES:
            return None
        idx.append(STATES[s])
    idx = sorted(set(idx))
    runs, start, prev = [], idx[0], idx[0]
    for x in idx[1:]:
        if x != prev + 1:
            runs.append((start, prev))
            start = x
        prev = x
    runs.append((start, prev))
    return runs


def full_addr(fam):
    return (0, 2 ** 32 - 1) if fam == 4 else (0, 2 ** 128 - 1)


def parse_addr(v, fam):
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        return None
    if net.version != fam:
        return None
    return (int(net.network_address), int(net.broadcast_address))


class Line:
    """Tek bir iptables kural satırı."""
    __slots__ = ("raw", "chain", "target", "pkts", "nbytes", "atoms", "opaque", "kind", "reject")

    def __init__(self):
        self.raw = ""
        self.chain = ""
        self.target = None
        self.pkts = None
        self.nbytes = None
        self.atoms = []     # [(proto, src, dst, sport, dport, state, iif, oif)], iif/oif: ad veya None
        self.opaque = False  # modellenemeyen ek koşul var: kutusundan AZINI eşleyebilir
        self.kind = "pass"   # allow | deny | return | pass | jump
        self.reject = False


def classify_target(t):
    if not t:
        return "pass"
    if t == "ACCEPT":
        return "allow"
    if t in ("DROP", "REJECT"):
        return "deny"
    if t == "RETURN":
        return "return"
    if re.fullmatch(r"ufw6?-user-limit-accept", t):
        return "allow"
    if re.fullmatch(r"ufw6?-user-limit", t):
        return "deny"
    if t in NONTERMINAL_TARGETS or re.fullmatch(r"ufw6?-(\w+-)?logging-\w+", t):
        return "pass"
    return "jump"


def parse_rule_line(raw, fam):
    """'-A zincir ...' satırını Line'a çevirir; kural satırı değilse None."""
    s = raw.strip()
    ln = Line()
    m = re.match(r"^\[(\d+):(\d+)\]\s*(.*)$", s)
    if m:
        ln.pkts, ln.nbytes, s = int(m.group(1)), int(m.group(2)), m.group(3)
    try:
        tok = shlex.split(s)
    except ValueError:
        tok = s.split()
    if len(tok) < 2 or tok[0] not in ("-A", "--append"):
        return None
    ln.raw, ln.chain = s, tok[1]

    proto, src, dst = FULL_PROTO, full_addr(fam), full_addr(fam)
    sports, dports, states = [FULL_PORT], [FULL_PORT], [FULL_STATE]
    iif = oif = None
    neg = after_target = False
    i = 2
    while i < len(tok):
        t = tok[i]
        if t == "!":
            neg = True
            i += 1
            continue
        nxt = tok[i + 1] if i + 1 < len(tok) else ""
        if t in ("-p", "--protocol"):
            i += 1
            pr = parse_proto(nxt)
            if neg or pr is None:
                ln.opaque = True
            else:
                proto = pr
        elif t in ("-s", "--source", "--src", "-d", "--destination", "--dst"):
            i += 1
            a = parse_addr(nxt, fam)
            if neg or a is None:
                ln.opaque = True
            elif t in ("-s", "--source", "--src"):
                src = a
            else:
                dst = a
        elif t in ("-i", "--in-interface", "-o", "--out-interface"):
            i += 1
            if neg or nxt.endswith("+"):
                ln.opaque = True
            elif t in ("-i", "--in-interface"):
                iif = nxt
            else:
                oif = nxt
        elif t in ("--dport", "--destination-port", "--dports", "--destination-ports",
                   "--sport", "--source-port", "--sports", "--source-ports"):
            i += 1
            ivs = parse_ports(nxt)
            if neg or ivs is None:
                ln.opaque = True
            elif t.startswith("--d"):
                dports = ivs
            else:
                sports = ivs
        elif t in ("--ctstate", "--state"):
            i += 1
            st = parse_states(nxt)
            if neg or st is None:
                ln.opaque = True
            else:
                states = st
        elif t in ("-m", "--match"):
            i += 1
            if nxt not in KNOWN_MODULES:
                ln.opaque = True
        elif t == "--comment":
            i += 1
        elif t in ("-j", "--jump", "-g", "--goto"):
            i += 1
            ln.target = nxt
            after_target = True
        elif t.startswith("-"):
            # Modellenmeyen seçenek: hedeften önceyse ek eşleşme koşuludur
            if not after_target:
                ln.opaque = True
            while i + 1 < len(tok) and tok[i + 1] != "!" and not re.match(r"^--?[a-zA-Z]", tok[i + 1]):
                i += 1
        neg = False
        i += 1

    ln.kind = classify_target(ln.target)
    ln.reject = ln.target == "REJECT" or bool(re.fullmatch(r"ufw6?-user-limit", ln.target or ""))
    ln.atoms = [(proto, src, dst, sp, dp, st, iif, oif) for sp in sports for dp in dports for st in states]
    return ln


def parse_dump(text, fam=None):
    """iptables-save çıktısı -> (fam, {zincir: [Line]}, {zincir: (politika, pkts)})."""
    if fam is None:
        fam = 6 if ("ip6tables-save" in text or re.search(r" -[sd] [0-9a-fA-F]*:[0-9a-fA-F:]*/", text)) else 4
    chains, policies = {}, {}
    table = "filter"
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("*"):
            table = s[1:]
            continue
        if table != "filter" or not s or s.startswith("#"):
            continue
        if s.startswith(":"):
            m = re.match(r"^:(\S+)\s+(\S+)(?:\s+\[(\d+):\d+\])?", s)
            if m:
                chains.setdefault(m.group(1), [])
                policies[m.group(1)] = (m.group(2), int(m.group(3)) if m.group(3) else None)
            continue
        ln = parse_rule_line(s, fam)
        if ln:
            chains.setdefault(ln.chain, []).append(ln)
    return fam, chains, policies


# =====================================================================
# Kutu (çok boyutlu aralık) geometrisi
# =====================================================================

def intersects(a, b):
    return all(x[0] <= y[1] and y[0] <= x[1] for x, y in zip(a, b))


def subset(a, b):
    """a ⊆ b"""
    return all(y[0] <= x[0] and x[1] <= y[1] for x, y in zip(a, b))


def intersection(a, b):
    return tuple((max(x[0], y[0]), min(x[1], y[1])) for x, y in zip(a, b))


def subtract(b, a):
    """b \\ a (kesiştikleri varsayılır) -> ayrık kutular listesi."""
    out, cur = [], list(b)
    for d in range(len(b)):
        blo, bhi = cur[d]
        alo, ahi = a[d]
        if blo < alo:
            piece = list(cur)
            piece[d] = (blo, alo - 1)
            out.append(tuple(piece))
            blo = alo
        if bhi > ahi:
            piece = list(cur)
            piece[d] = (ahi + 1, bhi)
            out.append(tuple(piece))
            bhi = ahi
        cur[d] = (blo, bhi)
    return out


def remainder(region, cover):
    """region içinde cover kutularının kapsamadığı kısım."""
    rem = list(region)
    for a in cover:
        nxt = []
        for b in rem:
            if intersects(b, a):
                nxt.extend(subtract(b, a))
            else:
                nxt.append(b)
        rem = nxt
        if len(rem) > COVER_BUDGET:
            raise BudgetExceeded()
        if not rem:
            break
    return rem


def any_intersect(xs, ys):
    return any(intersects(x, y) for x in xs for y in ys)


# =====================================================================
# Kural grubu (UFW'de bir "tuple", ham iptables'ta tek satır)
# =====================================================================

class Group:
    def __init__(self, lines, ref, label):
        self.lines = lines          # analiz edilen zincirdeki satırlar
        self.ref = ref              # kullanıcıya gösterilen kimlik ("#3" ya da "INPUT:3")
        self.label = label
        self.pos = 0                # zincirdeki sıra (0 tabanlı)
        self.block = None           # UFW metin bloğu (uygulama için)
        self.ufw_num = None
        self.fields = None          # UFW tuple alanları
        self.all_boxes = []         # tüm satırların kutuları (sıra kısıtı için)
        self.term_boxes = []        # sonlandıran satırların kutuları
        self.solid_boxes = []       # sonlandıran ve kesin (opak olmayan) kutular
        self.verdict = None         # allow | deny | limit | None
        self.terminal = False
        self.has_jump = False
        self.reject = False
        self.weight = None          # bu grupta sonlanan paket sayısı
        self.cost = max(1, len(lines))

    def finalize(self, ifmap):
        def box(atom):
            proto, src, dst, sp, dp, st, iif, oif = atom
            top = len(ifmap) + 1
            fi = (ifmap[iif], ifmap[iif]) if iif else (0, top)
            fo = (ifmap[oif], ifmap[oif]) if oif else (0, top)
            return (proto, src, dst, sp, dp, st, fi, fo)

        verdicts = set()
        limit = False
        for ln in self.lines:
            boxes = [box(a) for a in ln.atoms]
            self.all_boxes.extend(boxes)
            if ln.kind == "jump":
                self.has_jump = True
            if ln.kind in ("allow", "deny", "return"):
                self.terminal = True
                self.term_boxes.extend(boxes)
                if ln.kind != "return":
                    verdicts.add(ln.kind)
                    if not ln.opaque:
                        self.solid_boxes.extend(boxes)
                if ln.reject:
                    self.reject = True
            if re.fullmatch(r"ufw6?-user-limit(-accept)?", ln.target or ""):
                limit = True
        if limit:
            self.verdict = "limit"
        elif len(verdicts) == 1:
            self.verdict = verdicts.pop()
        if all(ln.pkts is not None for ln in self.lines):
            self.weight = sum(ln.pkts for ln in self.lines if ln.kind in ("allow", "deny", "return"))


class Finding:
    def __init__(self, sev, code, title, detail="", refs=(), fix=""):
        self.sev, self.code, self.title, self.detail = sev, code, title, detail
        self.refs, self.fix = list(refs), fix

    def to_dict(self):
        return {"severity": SEV_NAME[self.sev], "level": self.sev, "code": self.code,
                "title": self.title, "detail": self.detail, "rules": self.refs, "fix": self.fix}


class Chain:
    def __init__(self, name, fam, groups, default=None, entered=None, direction="in"):
        self.name, self.fam, self.groups = name, fam, groups
        self.default = default      # allow | deny | None (varsayılan politika)
        self.entered = entered      # zincire giren paket sayısı (None: bilinmiyor)
        self.direction = direction  # in | out | forward
        self.ifnames = {}
        self.findings = []
        self.perf = None
        self.prec = []              # prec[j]: j'den önce gelmek ZORUNDA olanların bit maskesi
        names = sorted({a[k] for g in groups for ln in g.lines for a in ln.atoms for k in (6, 7) if a[k]})
        self.ifmap = {n: i + 1 for i, n in enumerate(names)}
        for pos, g in enumerate(groups):
            g.pos = pos
            g.finalize(self.ifmap)

    # ---------- metinleştirme ----------
    def describe_box(self, b):
        proto, src, dst, sp, dp, st, fi, fo = b
        parts = []
        if proto != FULL_PROTO:
            parts.append(PROTO_NAME.get(proto[0], str(proto[0])) if proto[0] == proto[1] else f"proto {proto[0]}-{proto[1]}")
        if src != full_addr(self.fam):
            parts.append("kaynak " + fmt_addr(src, self.fam))
        if dst != full_addr(self.fam):
            parts.append("hedef " + fmt_addr(dst, self.fam))
        if sp != FULL_PORT:
            parts.append("kaynak port " + fmt_port(sp))
        if dp != FULL_PORT:
            parts.append("port " + fmt_port(dp))
        rev = {v: k for k, v in self.ifmap.items()}
        if fi[0] == fi[1] and fi[0] in rev:
            parts.append("giriş " + rev[fi[0]])
        if fo[0] == fo[1] and fo[0] in rev:
            parts.append("çıkış " + rev[fo[0]])
        return ", ".join(parts) or "tüm trafik"


def fmt_port(iv):
    return str(iv[0]) if iv[0] == iv[1] else f"{iv[0]}-{iv[1]}"


def fmt_addr(iv, fam):
    cls = ipaddress.IPv4Address if fam == 4 else ipaddress.IPv6Address
    nets = list(ipaddress.summarize_address_range(cls(iv[0]), cls(iv[1])))
    txt = ", ".join(str(n.network_address) if n.num_addresses == 1 else str(n) for n in nets[:3])
    return txt + (" ..." if len(nets) > 3 else "")


def fmt_int(n):
    return f"{n:,}".replace(",", ".")


# =====================================================================
# Çakışma (anomali) analizi
# =====================================================================

def verdict_tr(v):
    return {"allow": "ALLOW", "deny": "DENY", "limit": "LIMIT"}.get(v, "?")


def analyze_conflicts(ch):
    """Gölgeleme, gereksizlik, korelasyon ve genelleme tespiti (Al-Shaer & Hamed sınıflaması)."""
    G = ch.groups
    n = len(G)
    exceptions = 0
    for j in range(n):
        gj = G[j]
        if not gj.terminal or gj.verdict is None:
            continue
        rem = list(gj.term_boxes)
        takers = []     # gj'nin trafiğinden pay alan önceki kurallar
        try:
            for i in range(j):
                gi = G[i]
                if not gi.solid_boxes or gi.verdict is None:
                    continue
                if any_intersect(rem, gi.solid_boxes):
                    takers.append(gi)
                    rem = remainder(rem, gi.solid_boxes)
                    if not rem:
                        break
        except BudgetExceeded:
            ch.findings.append(Finding(INFO, "ANALIZ-SINIRI", f"{gj.ref} için kapsama analizi çok karmaşık, atlandı",
                                       refs=[gj.ref]))
            continue

        hits = f" (isabet: {fmt_int(gj.weight)})" if gj.weight is not None else ""
        if takers and not rem:
            names = ", ".join(t.ref for t in takers)
            if all(t.verdict == gj.verdict for t in takers):
                ch.findings.append(Finding(
                    LOW, "GEREKSIZ", f"{gj.ref} gereksiz: önceki kural(lar) aynı kararı zaten veriyor",
                    f"{gj.label}\nTamamı {names} tarafından kapsanıyor{hits}. Silmek zinciri kısaltır.",
                    [gj.ref] + [t.ref for t in takers], f"Kuralı silin: {gj.ref}"))
            else:
                if gj.verdict == "deny":
                    sev, what = HIGH, "Engelleme kuralı HİÇ çalışmıyor; engellemek istediğiniz trafik geçiyor."
                elif gj.verdict == "limit":
                    sev, what = MEDIUM, "Hız limiti HİÇ uygulanmıyor."
                else:
                    sev, what = MEDIUM, "İzin kuralı HİÇ çalışmıyor; servis erişilemez olabilir."
                ch.findings.append(Finding(
                    sev, "GOLGELEME", f"{gj.ref} gölgelenmiş: {names} yüzünden hiç eşleşmiyor",
                    f"{gj.label}\n{what}{hits}\nÖnce gelen: " +
                    "; ".join(f"{t.ref} [{verdict_tr(t.verdict)}] {t.label}" for t in takers),
                    [gj.ref] + [t.ref for t in takers],
                    f"{gj.ref} kuralını {takers[0].ref} kuralının ÜSTÜNE taşıyın ya da silin." +
                    move_hint(gj, takers[0])))
            continue

        for gi in takers:
            if gi.verdict == gj.verdict:
                continue
            inter = next(intersection(x, y) for x in gj.term_boxes for y in gi.solid_boxes if intersects(x, y))
            where = ch.describe_box(inter)
            if all(any(subset(y, x) for x in gj.term_boxes) for y in gi.solid_boxes):
                exceptions += 1     # önce dar istisna, sonra genel kural: bilinçli desen
                continue
            if gj.verdict == "deny":
                ch.findings.append(Finding(
                    MEDIUM, "KISMI-ETKISIZ", f"{gj.ref} [DENY] kısmen etkisiz: {gi.ref} önce izin veriyor",
                    f"{gj.label}\nKesişim ({where}) için {gi.ref} [{verdict_tr(gi.verdict)}] {gi.label} geçerli; "
                    f"bu trafik ENGELLENMİYOR.",
                    [gj.ref, gi.ref],
                    f"Engelleme önce gelmeli: {gj.ref} kuralını {gi.ref} kuralının üstüne taşıyın." + move_hint(gj, gi)))
            else:
                ch.findings.append(Finding(
                    LOW, "KORELASYON", f"{gj.ref} [{verdict_tr(gj.verdict)}] ile {gi.ref} [{verdict_tr(gi.verdict)}] sıraya bağımlı",
                    f"{gj.label}\nKesişim ({where}) için önce gelen {gi.ref} {gi.label} kazanıyor. "
                    "Niyetiniz buysa sorun yok; değilse sırayı değiştirin.",
                    [gj.ref, gi.ref]))

    # Yukarı yönlü gereksizlik: sonraki daha genel kural aynı kararı veriyor, arada farklı karar yok
    flagged = {f.refs[0] for f in ch.findings if f.code in ("GEREKSIZ", "GOLGELEME")}
    for i in range(n):
        gi = G[i]
        if not gi.terminal or gi.verdict is None or gi.ref in flagged:
            continue
        for j in range(i + 1, n):
            gj = G[j]
            if not any_intersect(gi.all_boxes, gj.all_boxes):
                continue
            if gj.verdict == gi.verdict and gj.solid_boxes and len(gj.lines) == len(gi.lines) \
                    and all(any(subset(x, y) for y in gj.solid_boxes) for x in gi.term_boxes):
                ch.findings.append(Finding(
                    LOW, "GEREKSIZ", f"{gi.ref} gereksiz: sonraki {gj.ref} zaten kapsıyor",
                    f"{gi.label}\n{gj.ref} {gj.label} aynı kararı daha geniş kapsamla veriyor ve arada "
                    "farklı karar veren kural yok. Silmek zinciri kısaltır.",
                    [gi.ref, gj.ref], f"Kuralı silin: {gi.ref}"))
            break   # ilk kesişen sonraki kural belirleyicidir

    if exceptions:
        ch.findings.append(Finding(
            INFO, "ISTISNA", f"{exceptions} adet 'önce dar istisna, sonra genel kural' deseni bulundu",
            "Bu desen genelde bilinçlidir (ör. önce tek IP'yi engelle, sonra servise izin ver)."))


def move_hint(g, before):
    """UFW için 'sil + araya ekle' komut önerisi (en iyi çaba; uygulamadan önce doğrulayın)."""
    if g.ufw_num is None or before.ufw_num is None or not g.fields:
        return ""
    spec = ufw_rule_spec(g.fields)
    if not spec:
        return ""
    route = "route " if g.fields["route"] else ""
    return (f"\n    sudo ufw delete {g.ufw_num}"
            f"\n    sudo ufw {route}insert {before.ufw_num} {spec}")


# =====================================================================
# Güvenlik kontrolleri
# =====================================================================

def analyze_security(ch):
    if ch.direction != "in":
        return
    full = full_addr(ch.fam)
    for g in ch.groups:
        if g.verdict not in ("allow", "limit"):
            continue
        seen = set()
        for b in g.term_boxes:
            proto, src, _dst, _sp, dp, st, fi, _fo = b
            lo_idx = ch.ifmap.get("lo")
            if src != full or (lo_idx and fi == (lo_idx, lo_idx)) or st[0] > STATES["NEW"]:
                continue
            if proto == FULL_PROTO and dp == FULL_PORT:
                if "ALL" not in seen:
                    seen.add("ALL")
                    ch.findings.append(Finding(
                        HIGH, "HER-SEYE-IZIN", f"{g.ref} tüm kaynaklardan tüm trafiğe izin veriyor",
                        f"{g.label}\nBu kuraldan sonraki hiçbir engelleme çalışmaz; güvenlik duvarı fiilen kapalıdır.",
                        [g.ref], "Kuralı silin ve yalnızca gereken port/kaynaklara izin verin."))
                continue
            if dp == FULL_PORT:
                continue
            width = dp[1] - dp[0] + 1
            if width > 1024 and "RANGE" not in seen:
                seen.add("RANGE")
                ch.findings.append(Finding(
                    MEDIUM, "GENIS-ARALIK", f"{g.ref} dünyaya {fmt_int(width)} portluk aralık açıyor ({fmt_port(dp)})",
                    g.label, [g.ref], "Aralığı daraltın veya kaynak IP ile sınırlayın."))
            for port, (name, sev) in SENSITIVE_PORTS.items():
                if not (dp[0] <= port <= dp[1]) or port in seen:
                    continue
                if not (proto[0] <= 6 <= proto[1] or proto[0] <= 17 <= proto[1]):
                    continue
                seen.add(port)
                if g.verdict == "limit":
                    continue    # hız limiti zaten var
                if port == 22:
                    ch.findings.append(Finding(
                        LOW, "SSH-ACIK", f"{g.ref} SSH (22) tüm dünyaya hız limitsiz açık",
                        g.label, [g.ref],
                        "Kaba kuvvete karşı 'ufw limit 22/tcp' kullanın veya kaynak IP ile sınırlayın."))
                elif sev > INFO:
                    ch.findings.append(Finding(
                        sev, "HASSAS-PORT", f"{g.ref} {name} ({port}) tüm dünyaya açık",
                        g.label, [g.ref], "Kaynağı güvenilen IP/alt ağ ile sınırlayın (ufw allow from <IP> to any port ...)."))


# =====================================================================
# Sıralama optimizasyonu: 1 | prec | Σ w_j C_j
# =====================================================================

def chain_cost(order, w, p, miss=0):
    pref = total = 0
    for j in order:
        pref += p[j]
        total += w[j] * pref
    return total + miss * pref


def order_is_safe(order, prec):
    """Önerilen sıra tüm kesişen çiftlerin göreli sırasını koruyor mu? (bağımsız doğrulama)"""
    seen = 0
    for j in order:
        if prec[j] & ~seen:
            return False
        seen |= 1 << j
    return True


def _local_search(order, w, p, prec):
    order = list(order)
    changed = True
    while changed:
        changed = False
        for k in range(len(order) - 1):
            a, b = order[k], order[k + 1]
            if not (prec[b] >> a) & 1 and w[b] * p[a] > w[a] * p[b]:
                order[k], order[k + 1] = b, a
                changed = True
    return order


def _heuristic(w, p, prec):
    """En yoğun 'zorunlu öncüller + kural' kümesini öne al (Sidney ayrışımına yakınsar) + yerel arama."""
    n = len(w)
    anc = [0] * n
    for j in range(n):
        m = prec[j]
        i = 0
        while m:
            if m & 1:
                anc[j] |= anc[i] | (1 << i)
            m >>= 1
            i += 1
    done, order = 0, []
    while len(order) < n:
        best = None
        for t in range(n):
            if (done >> t) & 1:
                continue
            req = (anc[t] | (1 << t)) & ~done
            W = P = 0
            for k in range(n):
                if (req >> k) & 1:
                    W += w[k]
                    P += p[k]
            if best is None or W * best[1] > best[0] * P:
                best = (W, P, req)
        req = best[2]
        members = [k for k in range(n) if (req >> k) & 1]   # artan sıra her zaman geçerlidir
        order.extend(members)
        done |= req
    cands = [_local_search(order, w, p, prec), _local_search(range(n), w, p, prec)]
    return min(cands, key=lambda o: chain_cost(o, w, p))


def _exact(w, p, prec, orig):
    """Geçerli ön-kümeler üzerinde DP. Eşitlikte mevcut sıraya en yakın çözümü seçer."""
    n = len(w)
    lower = [0] * n     # orijinalde j'den önce gelenler
    for j in range(n):
        for k in range(n):
            if orig[k] < orig[j]:
                lower[j] |= 1 << k
    frontier = {0: (0, 0, 0)}   # maske -> (maliyet, ters çevirme, süre)
    parent = {}
    states = 1
    for _ in range(n):
        nxt = {}
        for S, (cost, inv, ps) in frontier.items():
            for j in range(n):
                bit = 1 << j
                if S & bit or prec[j] & ~S:
                    continue
                S2 = S | bit
                p2 = ps + p[j]
                cand = (cost + w[j] * p2, inv + bin(lower[j] & ~S2).count("1"), p2)
                cur = nxt.get(S2)
                if cur is None or cand[:2] < cur[:2]:
                    nxt[S2] = cand
                    parent[S2] = j
        states += len(nxt)
        if states > DP_STATE_CAP:
            return None
        frontier = nxt
    order, S = [], (1 << n) - 1
    while S:
        j = parent[S]
        order.append(j)
        S &= ~(1 << j)
    return order[::-1]


def solve_order(w, p, prec):
    """Kısıtlar altında Σ w·C'yi minimize eden sıra. -> (sıra, kesin_mi)"""
    n = len(w)
    succ = [[] for _ in range(n)]
    for j in range(n):
        for i in range(j):
            if (prec[j] >> i) & 1:
                succ[i].append(j)
    # İsabeti olmayan ve isabetli hiçbir kuralın önünü tutmayan kurallar en sona gider
    need = [False] * n
    for j in range(n - 1, -1, -1):
        need[j] = w[j] > 0 or any(need[k] for k in succ[j])
    core = [j for j in range(n) if need[j]]
    tail = [j for j in range(n) if not need[j]]
    if not core:
        return list(range(n)), True
    idx = {j: k for k, j in enumerate(core)}
    cw, cp = [w[j] for j in core], [p[j] for j in core]
    cprec = []
    for j in core:
        m = 0
        for i in core:
            if (prec[j] >> i) & 1:
                m |= 1 << idx[i]
        cprec.append(m)
    sol = _exact(cw, cp, cprec, list(range(len(core)))) if len(core) <= 60 else None
    exact = sol is not None
    if sol is None:
        sol = _heuristic(cw, cp, cprec)
    order = [core[k] for k in sol] + tail
    if not order_is_safe(order, prec) or chain_cost(order, w, p) > chain_cost(range(n), w, p):
        return list(range(n)), False
    return order, exact


def analyze_performance(ch, min_packets):
    G = ch.groups
    n = len(G)
    ch.prec = [0] * n
    locks = 0
    for j in range(n):
        for i in range(j):
            if any_intersect(G[i].all_boxes, G[j].all_boxes):
                ch.prec[j] |= 1 << i
                locks += 1
    perf = {"available": False, "rules": n, "locks": locks}
    ch.perf = perf
    if n == 0:
        return
    if any(g.weight is None for g in G):
        perf["reason"] = "Paket sayaçları okunamadı (root gerekir veya canlı kurallar dosyayla eşleşmiyor)."
        return

    w = [g.weight for g in G]
    p = [g.cost for g in G]
    terminated = sum(w)
    miss = max(0, ch.entered - terminated) if ch.entered is not None else 0
    total = terminated + miss
    cur_order = list(range(n))
    cur = chain_cost(cur_order, w, p, miss)
    order, exact = solve_order(w, p, ch.prec)
    opt = chain_cost(order, w, p, miss)
    free = sorted(range(n), key=lambda j: (-w[j] * 1.0 / p[j], j))    # kısıtsız alt sınır (Smith kuralı)
    lower = chain_cost(free, w, p, miss)

    perf.update({
        "available": True, "exact": exact, "packets": total, "terminated": terminated, "miss": miss,
        "miss_known": ch.entered is not None, "cost_now": cur, "cost_opt": opt, "cost_lower": lower,
        "avg_now": cur / total if total else 0.0, "avg_opt": opt / total if total else 0.0,
        "efficiency": (opt / cur) if cur else 1.0,
        "gain_pct": (100.0 * (cur - opt) / cur) if cur else 0.0,
        "order": order, "changed": order != cur_order,
        "confident": total >= min_packets, "min_packets": min_packets,
        "approx": any(g.has_jump for g in G),
    })

    if total < min_packets:
        ch.findings.append(Finding(
            INFO, "AZ-ORNEK", f"{ch.name}: sıralama önerisi için yeterli trafik yok ({fmt_int(total)} paket < {fmt_int(min_packets)})",
            "Sayaçlar 'ufw reload' ve yeniden başlatmada sıfırlanır. Normal trafik altında bir süre bekleyip tekrar çalıştırın "
            "veya --sample ile belirli bir pencere ölçün."))
        return

    eff = perf["efficiency"]
    if perf["changed"] and eff < 0.95:
        sev = MEDIUM if eff < 0.70 else LOW
        new = " → ".join(G[j].ref for j in order)
        ch.findings.append(Finding(
            sev, "SIRALAMA", f"{ch.name}: kural sırası verimsiz (verim %{eff * 100:.0f}, kazanç %{perf['gain_pct']:.0f})",
            f"Paket başına ortalama kontrol: {perf['avg_now']:.2f} → {perf['avg_opt']:.2f}\n"
            f"Önerilen sıra: {new}\nKesişen kuralların göreli sırası korunur; hiçbir paketin kararı değişmez.",
            [G[j].ref for j in order if order.index(j) != j],
            "Uygulamak için: sudo ufw_audit.py --apply" if ch.groups[0].block is not None else
            "Kuralları önerilen sıraya göre yeniden yükleyin."))

    if perf["miss_known"] and total and miss / total >= 0.5 and n >= 3:
        ch.findings.append(Finding(
            LOW, "POLITIKAYA-DUSEN", f"{ch.name}: paketlerin %{100 * miss / total:.0f}'i hiçbir kurala uymadan tüm zinciri geziyor",
            f"{fmt_int(miss)} paket {n} kuralın hepsini kontrol ettirip varsayılan politikaya düşüyor. "
            "En yoğun istenmeyen kaynak/port için zincirin başına açık bir DENY kuralı eklemek bu yükü kaldırır "
            "(Telegram özetindeki 'en aktif kaynaklar' listesi adayları gösterir)."))

    dead = [g for g in G if g.terminal and g.weight == 0]
    if dead and total >= min_packets * 10:
        ch.findings.append(Finding(
            INFO, "ISABETSIZ", f"{ch.name}: {len(dead)} kural hiç isabet almamış",
            "Kullanılmayan kurallar her paket için boşuna kontrol edilir: " + ", ".join(g.ref for g in dead[:20]) +
            (" ..." if len(dead) > 20 else "") + "\nGerçekten gerekli mi gözden geçirin.",
            [g.ref for g in dead]))


def analyze_structure(ch):
    """Zincir büyüklüğü ve birleştirilebilir kurallar."""
    G = ch.groups
    if len(G) >= 100:
        ch.findings.append(Finding(
            LOW, "UZUN-ZINCIR", f"{ch.name}: {len(G)} kural var; iptables zinciri doğrusal taranır",
            "Çok sayıda tek-IP kuralı için ipset / nftables set kullanın (O(1) arama)."))
    # Yalnızca kaynak adresi farklı olan tek satırlık kurallar -> CIDR birleştirme
    shapes = {}
    for g in G:
        if len(g.lines) != 1 or len(g.term_boxes) != 1 or not g.solid_boxes:
            continue
        b = g.term_boxes[0]
        shapes.setdefault((g.verdict, b[0], b[2], b[3], b[4], b[5], b[6], b[7]), []).append(g)
    cls = ipaddress.IPv4Address if ch.fam == 4 else ipaddress.IPv6Address
    for members in shapes.values():
        if len(members) < 2 or any(m.term_boxes[0][1] == full_addr(ch.fam) for m in members):
            continue
        # Araya farklı kararlı kesişen kural giriyorsa birleştirme güvenli değildir
        lo, hi = members[0].pos, members[-1].pos
        if any(G[k] not in members and G[k].verdict != members[0].verdict and
               any(any_intersect(G[k].all_boxes, m.all_boxes) for m in members) for k in range(lo, hi + 1)):
            continue
        nets = []
        for m in members:
            s = m.term_boxes[0][1]
            nets.extend(ipaddress.summarize_address_range(cls(s[0]), cls(s[1])))
        merged = list(ipaddress.collapse_addresses(nets))
        if len(merged) < len(members):
            ch.findings.append(Finding(
                LOW, "BIRLESTIR", f"{ch.name}: {len(members)} kural {len(merged)} CIDR kuralına indirgenebilir",
                "Kurallar: " + ", ".join(m.ref for m in members[:15]) + (" ..." if len(members) > 15 else "") +
                "\nBirleşik: " + ", ".join(str(x) for x in merged[:8]) + (" ..." if len(merged) > 8 else ""),
                [m.ref for m in members]))
        elif len(members) >= 20:
            ch.findings.append(Finding(
                LOW, "IPSET", f"{ch.name}: aynı biçimde {len(members)} tek-kaynak kuralı var",
                "Bunları tek bir ipset/nftables set kuralına taşımak her paket için "
                f"{len(members)} kontrol yerine 1 kontrol demektir.", [m.ref for m in members[:20]]))


def analyze_fastpath(lines, name):
    """Durum takibi hızlı yolu (ESTABLISHED,RELATED → ACCEPT) zincirin başında mı?"""
    est = STATES["ESTABLISHED"]
    for pos, ln in enumerate(lines):
        if ln.kind == "allow" and not ln.opaque and any(a[5][0] <= est <= a[5][1] and a[5] != FULL_STATE for a in ln.atoms):
            before = [x for x in lines[:pos] if not (x.atoms and all(a[6] == "lo" for a in x.atoms))]
            if len(before) > 3:
                return Finding(
                    LOW, "HIZLI-YOL", f"{name}: ESTABLISHED/RELATED kuralı {pos + 1}. sırada",
                    "Trafiğin büyük çoğunluğu kurulu bağlantılara aittir; bu kural zincirin en başında olmalı.",
                    [f"{name}:{pos + 1}"], "Kuralı zincirin ilk satırlarına taşıyın.")
            return None
    if len(lines) >= 5:
        return Finding(
            MEDIUM, "HIZLI-YOL-YOK", f"{name}: ESTABLISHED/RELATED hızlı yol kuralı yok",
            "Her paket tüm kuralları geziyor. Başa '-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' eklemek "
            "tek başına en büyük performans kazancıdır.", [name])
    return None


# =====================================================================
# UFW yükleyici
# =====================================================================

class UfwFile:
    def __init__(self, path, text):
        self.path, self.text = path, text
        self.pre = self.post = ""
        self.blocks = []
        self.ok = False
        m = re.search(r"^### RULES ###\n", text, re.M)
        e = text.find("\n### END RULES ###")
        if not m or e < 0:
            return
        self.pre, self.post = text[:m.end()], text[e:]
        middle = text[m.end():e]
        self.blocks = [b.strip("\n") for b in re.split(r"\n(?=### tuple ###)", middle) if b.strip()]
        self.ok = self.render(self.blocks) == text      # gidiş-dönüş birebir olmalı

    def render(self, blocks):
        return self.pre + "".join("\n" + b + "\n" for b in blocks) + self.post


def parse_tuple(line):
    """'### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in [comment=hex]' -> alanlar"""
    body = line[len("### tuple ###"):].strip()
    comment = ""
    if " comment=" in body:
        body, hexc = body.split(" comment=", 1)
        try:
            comment = bytes.fromhex(hexc.strip()).decode("utf-8", "replace")
        except ValueError:
            comment = ""
    t = body.split()
    if len(t) not in (7, 9):
        return None
    f = {"action": t[0], "proto": t[1], "dport": t[2], "dst": t[3], "sport": t[4], "src": t[5],
         "dapp": "", "sapp": "", "comment": comment}
    f["iface"] = t[6] if len(t) == 7 else t[8]
    if len(t) == 9:
        f["dapp"] = "" if t[6] == "-" else t[6].replace("%20", " ")
        f["sapp"] = "" if t[7] == "-" else t[7].replace("%20", " ")
    f["route"] = f["action"].startswith("route:")
    act = f["action"].split(":", 1)[-1]
    f["log"] = "log-all" if act.endswith("_log-all") else ("log" if act.endswith("_log") else "")
    f["verb"] = act.split("_")[0]
    return f


def _anyaddr(a):
    return a in ("0.0.0.0/0", "::/0")


def ufw_label(f):
    s = f["verb"].upper()
    if f["route"]:
        s = "ROUTE " + s
    what = f["dapp"] or (f["dport"] if f["dport"] != "any" else "")
    if what and f["proto"] != "any" and not f["dapp"]:
        what += "/" + f["proto"]
    elif not what and f["proto"] != "any":
        what = "proto " + f["proto"]
    s += " " + (what or "tümü")
    s += " ← " + ("Anywhere" if _anyaddr(f["src"]) else f["src"])
    if f["sapp"] or f["sport"] != "any":
        s += " (kaynak port " + (f["sapp"] or f["sport"]) + ")"
    if not _anyaddr(f["dst"]):
        s += " → " + f["dst"]
    if "_" in f["iface"]:
        s += " [" + f["iface"].replace("!", " ").replace("_", " on ") + "]"
    elif f["iface"] == "out":
        s += " [out]"
    if f["comment"]:
        s += f"  # {f['comment']}"
    return s


def ufw_rule_spec(f):
    """Tuple'dan 'ufw insert N <spec>' için kural metni üretir (en iyi çaba)."""
    parts = [f["verb"]]
    for seg in f["iface"].split("!"):
        if "_" in seg:
            d, ifn = seg.split("_", 1)
            parts += [d, "on", ifn]
        elif seg in ("in", "out") and (seg == "out" or f["route"]):
            parts.append(seg)
    if f["log"]:
        parts.append(f["log"])
    if f["proto"] != "any" and not (f["dapp"] or f["sapp"]):
        parts += ["proto", f["proto"]]
    parts += ["from", "any" if _anyaddr(f["src"]) else f["src"]]
    if f["sapp"]:
        parts += ["app", shlex.quote(f["sapp"])]
    elif f["sport"] != "any":
        parts += ["port", f["sport"]]
    parts += ["to", "any" if _anyaddr(f["dst"]) else f["dst"]]
    if f["dapp"]:
        parts += ["app", shlex.quote(f["dapp"])]
    elif f["dport"] != "any":
        parts += ["port", f["dport"]]
    if f["comment"]:
        parts += ["comment", shlex.quote(f["comment"])]
    return " ".join(parts)


def read_kv(path):
    out = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", str(e)


def live_dump(fam):
    tool = "iptables-save" if fam == 4 else "ip6tables-save"
    if not shutil.which(tool):
        return None
    rc, out, _ = run([tool, "-c", "-t", "filter"])
    return out if rc == 0 and out.strip() else None


def subtract_dumps(new, old):
    """--sample: iki döküm arasındaki sayaç farkı (satırlar konum olarak eşleşir)."""
    a, b = new.splitlines(), old.splitlines()
    if len(a) != len(b):
        return new
    out = []
    for x, y in zip(a, b):
        mx, my = re.match(r"^\[(\d+):(\d+)\](.*)$", x), re.match(r"^\[(\d+):(\d+)\](.*)$", y)
        if mx and my and mx.group(3) == my.group(3):
            out.append(f"[{max(0, int(mx.group(1)) - int(my.group(1)))}:{max(0, int(mx.group(2)) - int(my.group(2)))}]{mx.group(3)}")
            continue
        px, py = re.match(r"^(:\S+ \S+) \[(\d+):(\d+)\]$", x), re.match(r"^(:\S+ \S+) \[(\d+):(\d+)\]$", y)
        if px and py and px.group(1) == py.group(1):
            out.append(f"{px.group(1)} [{max(0, int(px.group(2)) - int(py.group(2)))}:{max(0, int(px.group(3)) - int(py.group(3)))}]")
            continue
        out.append(x)
    return "\n".join(out)


def load_ufw(ufw_dir, dumps, defaults_path):
    """-> (zincirler, dosyalar, ortam bulguları, meta)"""
    env, chains, files = [], [], {}
    defaults = read_kv(defaults_path)
    conf = read_kv(os.path.join(ufw_dir, "ufw.conf"))
    meta = {"mode": "ufw", "enabled": conf.get("ENABLED", "").lower() == "yes",
            "loglevel": conf.get("LOGLEVEL", ""), "ipv6": defaults.get("IPV6", "yes").lower() == "yes"}

    def policy(key):
        v = defaults.get(key, "").upper()
        return "allow" if v == "ACCEPT" else ("deny" if v in ("DROP", "REJECT") else None)

    pol = {"input": policy("DEFAULT_INPUT_POLICY"), "output": policy("DEFAULT_OUTPUT_POLICY"),
           "forward": policy("DEFAULT_FORWARD_POLICY")}
    meta["policy"] = pol

    if conf and not meta["enabled"]:
        env.append(Finding(HIGH, "UFW-KAPALI", "UFW etkin değil (ENABLED=no)",
                           "Kurallar tanımlı olsa bile uygulanmıyor.", fix="sudo ufw enable"))
    if pol["input"] == "allow":
        env.append(Finding(HIGH, "POLITIKA-ACIK", "Varsayılan gelen politikası ACCEPT",
                           "Açıkça engellenmeyen her şey içeri giriyor.", fix="sudo ufw default deny incoming"))
    lvl = meta["loglevel"].lower()
    if lvl == "off":
        env.append(Finding(LOW, "LOG-KAPALI", "UFW loglama kapalı", "Engellenen bağlantılar kaydedilmiyor; "
                           "Telegram bildirimi de çalışmaz.", fix="sudo ufw logging low"))
    elif lvl in ("high", "full"):
        env.append(Finding(LOW, "LOG-YUKSEK", f"UFW loglama seviyesi '{lvl}'",
                           "Bu seviyede izin verilen paketler de loglanır: disk G/Ç ve CPU yükü artar, günlük ve "
                           "bildirim gürültüsü oluşur. Üretimde 'low' (yalnızca engellenenler) yeterlidir.",
                           fix="sudo ufw logging low"))

    num = 0
    seen_app = {}
    for fam, fname in ((4, "user.rules"), (6, "user6.rules")):
        path = os.path.join(ufw_dir, fname)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                uf = UfwFile(path, fh.read())
        except PermissionError:
            env.append(Finding(INFO, "YETKI", f"{path} okunamadı (root gerekir)"))
            continue
        except OSError:
            continue
        if not uf.blocks and not uf.ok:
            env.append(Finding(INFO, "BICIM", f"{path} beklenen biçimde değil, atlandı"))
            continue
        files[fam] = uf
        dump_chains, entered_src = {}, {}
        if dumps.get(fam):
            _, dump_chains, _ = parse_dump(dumps[fam], fam)
            for lines in dump_chains.values():
                for ln in lines:
                    if ln.target and ln.pkts is not None:
                        entered_src[ln.target] = entered_src.get(ln.target, 0) + ln.pkts

        per_chain = {}
        for bi, btext in enumerate(uf.blocks):
            blines = btext.split("\n")
            f = parse_tuple(blines[0])
            parsed = [x for x in (parse_rule_line(r, fam) for r in blines[1:]) if x]
            main = next((x.chain for x in parsed if re.fullmatch(r"ufw6?-user-(input|output|forward)", x.chain)), None)
            if not f or not main:
                env.append(Finding(INFO, "BICIM", f"{fname}: ayrıştırılamayan blok atlandı", blines[0]))
                continue
            key = None
            if f["dapp"] or f["sapp"]:
                key = (fam, f["dapp"] or f["dport"], f["dst"], f["sapp"] or f["sport"], f["src"], f["iface"], f["action"])
            if key and key in seen_app:
                n_ = seen_app[key]
            else:
                num += 1
                n_ = num
                if key:
                    seen_app[key] = n_
            g = Group([x for x in parsed if x.chain == main], f"#{n_}", ufw_label(f) + (" (v6)" if fam == 6 else ""))
            g.block, g.ufw_num, g.fields = bi, n_, f
            per_chain.setdefault(main, []).append(g)

        for cname, groups in per_chain.items():
            flat = [ln for g in groups for ln in g.lines]
            live = dump_chains.get(cname)
            if live is not None and len(live) == len(flat) and all(a.target == b.target for a, b in zip(live, flat)):
                for a, b in zip(live, flat):
                    b.pkts, b.nbytes = a.pkts, a.nbytes
                entered = entered_src.get(cname)
            else:
                entered = None
                if live is not None:
                    env.append(Finding(INFO, "ESLESMEDI", f"{cname}: canlı kurallar dosyayla eşleşmiyor",
                                       "Sayaçlar kullanılamadı; 'sudo ufw reload' sonrası tekrar deneyin."))
            suffix = cname.rsplit("-", 1)[-1]
            direction = {"input": "in", "output": "out", "forward": "forward"}[suffix]
            chains.append(Chain(cname, fam, groups, pol[suffix], entered, direction))

        before = dump_chains.get(("ufw" if fam == 4 else "ufw6") + "-before-input")
        if before:
            fp = analyze_fastpath(before, before[0].chain)
            if fp:
                env.append(fp)
    return chains, files, env, meta


def load_generic(text, fam, only):
    fam, dump_chains, policies = parse_dump(text, fam)
    env, chains = [], []
    entered_src = {}
    for lines in dump_chains.values():
        for ln in lines:
            if ln.target and ln.pkts is not None:
                entered_src[ln.target] = entered_src.get(ln.target, 0) + ln.pkts
    builtin = ("INPUT", "FORWARD", "OUTPUT")
    for name, lines in dump_chains.items():
        if only and name not in only:
            continue
        if not only and len(lines) < 2 and name not in builtin:
            continue
        if not lines:
            continue
        groups = [Group([ln], f"{name}:{k + 1}", re.sub(r"^-A \S+\s*", "", ln.raw)) for k, ln in enumerate(lines)]
        pname, ppk = policies.get(name, ("-", None))
        default = "allow" if pname == "ACCEPT" else ("deny" if pname in ("DROP", "REJECT") else None)
        if name in builtin:
            entered = (sum(ln.pkts for ln in lines if ln.kind in ("allow", "deny") and ln.pkts is not None) + ppk) \
                if ppk is not None else None
        else:
            entered = entered_src.get(name)
        direction = {"INPUT": "in", "OUTPUT": "out", "FORWARD": "forward"}.get(name, "sub")
        chains.append(Chain(name, fam, groups, default, entered, direction))
        if name == "INPUT":
            if pname == "ACCEPT" and not any(ln.kind == "deny" and not ln.opaque and ln.atoms[0][:5] ==
                                             (FULL_PROTO, full_addr(fam), full_addr(fam), FULL_PORT, FULL_PORT)
                                             for ln in lines):
                env.append(Finding(HIGH, "POLITIKA-ACIK", "INPUT varsayılan politikası ACCEPT ve sonda genel DROP yok",
                                   "Açıkça engellenmeyen her şey içeri giriyor.", fix="iptables -P INPUT DROP (önce izin kurallarını doğrulayın)"))
            fp = analyze_fastpath(lines, name)
            if fp:
                env.append(fp)
    meta = {"mode": "iptables", "policy": {k: v[0] for k, v in policies.items() if k in builtin}}
    return chains, env, meta


# =====================================================================
# Uygulama (yalnızca UFW; karar değiştirmeyen yeniden sıralama)
# =====================================================================

def build_plan(chains, files):
    """-> {fam: yeni blok listesi} (değişiklik olan dosyalar için)"""
    plan = {}
    for ch in chains:
        pf = ch.perf or {}
        if not (pf.get("available") and pf.get("confident") and pf.get("changed")):
            continue
        uf = files.get(ch.fam)
        if not uf or not uf.ok:
            continue
        if not order_is_safe(pf["order"], ch.prec):
            continue
        blocks = plan.setdefault(ch.fam, list(uf.blocks))
        slots = [g.block for g in ch.groups]                 # bu zincirin dosyadaki konumları
        for slot, j in zip(slots, pf["order"]):
            blocks[slot] = uf.blocks[ch.groups[j].block]
    return {fam: b for fam, b in plan.items() if b != files[fam].blocks}


def apply_plan(plan, files, log):
    stamp = time.strftime("%Y%m%d_%H%M%S")
    backups = []
    try:
        for fam, blocks in plan.items():
            uf = files[fam]
            new = uf.render(blocks)
            if sorted(blocks) != sorted(uf.blocks):
                raise RuntimeError("iç tutarlılık hatası: blok kümesi değişti")
            bak = f"{uf.path}.{stamp}"
            shutil.copy2(uf.path, bak)
            backups.append((uf.path, bak))
            log(f"Yedek: {bak}")
            tool = "iptables-restore" if fam == 4 else "ip6tables-restore"
            tmp = uf.path + ".audit-new"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(new)
            shutil.copymode(uf.path, tmp)
            st = os.stat(uf.path)
            os.chown(tmp, st.st_uid, st.st_gid)
            if shutil.which(tool):
                rc_old, _, _ = run([tool, "--test", "-n", uf.path])
                rc_new, _, err = run([tool, "--test", "-n", tmp])
                if rc_old == 0 and rc_new != 0:
                    os.unlink(tmp)
                    raise RuntimeError(f"yeni kural dosyası doğrulanamadı: {err.strip()}")
            os.replace(tmp, uf.path)
        rc, out, err = run(["ufw", "reload"], timeout=120)
        if rc != 0:
            raise RuntimeError(f"ufw reload başarısız: {(err or out).strip()}")
    except Exception as e:      # geri al
        for path, bak in backups:
            shutil.copy2(bak, path)
        if backups:
            run(["ufw", "reload"], timeout=120)
        log(f"HATA: {e}. Değişiklikler geri alındı.")
        return False
    log("Yeni sıra uygulandı ve UFW yeniden yüklendi. (Sayaçlar sıfırlandı; etkisini ölçmek için bir süre sonra tekrar çalıştırın.)")
    return True


# =====================================================================
# Raporlama
# =====================================================================

class Painter:
    def __init__(self, enabled):
        self.on = enabled

    def c(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.on else s


def score_of(findings, chains):
    s = 100
    for f in findings:
        s -= {HIGH: 25, MEDIUM: 10, LOW: 3, INFO: 0}[f.sev]
    return max(0, s)


def efficiency_verdict(eff):
    if eff >= 0.95:
        return "Mükemmel optimizasyon"
    if eff >= 0.70:
        return "Fena değil, gelişebilir"
    return "Verimsiz: işlemci boşa çalışıyor"


def render_text(chains, env, meta, color, verbose):
    P = Painter(color)
    out = []
    findings = sorted(env + [f for ch in chains for f in ch.findings], key=lambda f: -f.sev)
    counts = {s: sum(1 for f in findings if f.sev == s) for s in (HIGH, MEDIUM, LOW, INFO)}
    out.append(P.c("1", f"UFW Kural Seti Denetimi  ·  {socket.gethostname()}  ·  {time.strftime('%Y-%m-%d %H:%M')}"))
    out.append("─" * 72)
    nrules = sum(len(ch.groups) for ch in chains)
    out.append(f"Mod: {meta['mode']}   Zincir: {len(chains)}   Kural: {nrules}   Puan: {score_of(findings, chains)}/100")
    if meta["mode"] == "ufw":
        pol = meta["policy"]
        out.append(f"UFW: {'etkin' if meta['enabled'] else 'KAPALI'}   Loglama: {meta['loglevel'] or '?'}   "
                   f"Varsayılan: gelen={pol['input'] or '?'} giden={pol['output'] or '?'} yönlendirme={pol['forward'] or '?'}")
    out.append("Bulgular: " + "  ".join(P.c(SEV_COLOR[s], f"{SEV_NAME[s]} {counts[s]}") for s in (HIGH, MEDIUM, LOW, INFO)))
    out.append("")

    out.append(P.c("1", "BULGULAR"))
    shown = [f for f in findings if verbose or f.sev > INFO or f.code in ("AZ-ORNEK", "YETKI", "ESLESMEDI")]
    if not shown:
        out.append("  ✔ Sorun bulunamadı.")
    for f in shown:
        out.append(P.c(SEV_COLOR[f.sev], f"  [{SEV_NAME[f.sev]}] {f.code}") + f"  {f.title}")
        for line in f.detail.splitlines():
            out.append("      " + line)
        if f.fix:
            out.append(P.c("32", "      ➜ " + f.fix.replace("\n", "\n      ")))
    hidden = len(findings) - len(shown)
    if hidden:
        out.append(f"  (+{hidden} bilgi notu; görmek için --verbose)")
    out.append("")

    out.append(P.c("1", "SIRALAMA PERFORMANSI"))
    for ch in chains:
        pf = ch.perf or {}
        out.append(P.c("1", f"  {ch.name}") + f"  ({len(ch.groups)} kural, {pf.get('locks', 0)} sıra kilidi)")
        if not pf.get("available"):
            out.append("      " + pf.get("reason", "Analiz edilecek kural yok."))
            for g in ch.groups if verbose else []:
                out.append(f"      {g.ref:>6}  {g.label}")
            continue
        total = pf["packets"]
        out.append(f"      {'kural':>6} {'isabet':>12} {'pay':>6} {'maliyet':>7}  tanım")
        for g in ch.groups:
            share = (100.0 * g.weight / total) if total else 0.0
            out.append(f"      {g.ref:>6} {fmt_int(g.weight):>12} {share:>5.1f}% {g.cost:>7}  {g.label[:70]}")
        if pf["miss_known"]:
            share = (100.0 * pf["miss"] / total) if total else 0.0
            out.append(f"      {'—':>6} {fmt_int(pf['miss']):>12} {share:>5.1f}% {'':>7}  (hiçbir kurala uymadı → varsayılan politika)")
        out.append(f"      Örneklem: {fmt_int(total)} paket   Toplam kontrol: {fmt_int(pf['cost_now'])}   "
                   f"Ortalama: {pf['avg_now']:.2f} kontrol/paket")
        if not pf["confident"]:
            out.append(P.c("33", f"      Yetersiz örneklem (< {fmt_int(pf['min_packets'])} paket): sıralama önerisi verilmedi."))
            continue
        eff = pf["efficiency"]
        col = "32" if eff >= 0.95 else ("33" if eff >= 0.70 else "31")
        out.append(P.c(col, f"      Verim: %{eff * 100:.1f} — {efficiency_verdict(eff)}") +
                   f"   (en iyi olası: {fmt_int(pf['cost_opt'])} kontrol, "
                   f"{'kesin optimum' if pf['exact'] else 'sezgisel çözüm'})")
        if pf["approx"]:
            out.append("      Not: alt zincire atlayan kurallar var; maliyet yaklaşık hesaplandı.")
        if pf["changed"]:
            out.append(f"      Önerilen sıra (kazanç %{pf['gain_pct']:.1f}, {pf['avg_now']:.2f} → {pf['avg_opt']:.2f} kontrol/paket):")
            for newpos, j in enumerate(pf["order"]):
                g = ch.groups[j]
                mark = "  " if j == newpos else ("↑ " if j > newpos else "↓ ")
                out.append(f"        {newpos + 1:>3}. {mark}{g.ref:>6}  {g.label[:66]}")
            if pf["cost_lower"] < pf["cost_opt"]:
                out.append(f"      Kilitler olmasaydı alt sınır {fmt_int(pf['cost_lower'])} olurdu; kesişen kurallar "
                           "karar değişmesin diye yer değiştirmedi.")
        else:
            out.append("      Mevcut sıra, kesişen kuralları bozmadan elde edilebilecek en iyi sıra.")
    out.append("")
    out.append(P.c("2", "Not: Araç kararları değiştirmeyen yeniden sıralamayı kanıtlanabilir biçimde önerir; güvenlik "
                        "bulguları ise niyet gerektirir. Uygulamadan önce bir uzmanın gözden geçirmesi önerilir."))
    return "\n".join(out)


def render_json(chains, env, meta):
    findings = sorted(env + [f for ch in chains for f in ch.findings], key=lambda f: -f.sev)
    return json.dumps({
        "version": VERSION, "host": socket.gethostname(), "time": int(time.time()), "meta": meta,
        "score": score_of(findings, chains),
        "findings": [f.to_dict() for f in findings],
        "chains": [{
            "name": ch.name, "family": ch.fam, "default": ch.default,
            "rules": [{"ref": g.ref, "label": g.label, "verdict": g.verdict, "hits": g.weight, "cost": g.cost}
                      for g in ch.groups],
            "performance": ({k: v for k, v in ch.perf.items() if k != "order"} |
                            {"proposed_order": [ch.groups[j].ref for j in ch.perf.get("order", [])]})
            if ch.perf else None,
        } for ch in chains],
    }, ensure_ascii=False, indent=2)


def render_telegram(chains, env, meta):
    findings = sorted(env + [f for ch in chains for f in ch.findings], key=lambda f: -f.sev)
    important = [f for f in findings if f.sev >= LOW]
    counts = {s: sum(1 for f in findings if f.sev == s) for s in (HIGH, MEDIUM, LOW)}
    head = "🚨" if counts[HIGH] else ("⚠️" if counts[MEDIUM] else "✅")
    lines = [f"{head} UFW Kural Seti Denetimi — {socket.gethostname()}",
             f"Puan: {score_of(findings, chains)}/100 · Kritik {counts[HIGH]} · Uyarı {counts[MEDIUM]} · Düşük {counts[LOW]}", ""]
    for f in important[:12]:
        lines.append(f"{SEV_ICON[f.sev]} {f.title}")
        if f.fix and f.sev >= MEDIUM:
            lines.append("   ➜ " + f.fix.splitlines()[0])
    if len(important) > 12:
        lines.append(f"… +{len(important) - 12} bulgu daha")
    for ch in chains:
        pf = ch.perf or {}
        if pf.get("available") and pf.get("confident"):
            lines.append(f"\n📈 {ch.name}: verim %{pf['efficiency'] * 100:.0f}, "
                         f"{pf['avg_now']:.2f} kontrol/paket" +
                         (f" → {pf['avg_opt']:.2f} (öneri var)" if pf["changed"] else " (optimum)"))
    lines.append("\nAyrıntı: sudo ufw_audit.py")
    return "\n".join(lines)[:4000]


def send_telegram(text):
    conf = read_kv(TELEGRAM_CONF)
    token, chat = conf.get("TELEGRAM_TOKEN"), conf.get("CHAT_ID")
    if not token or not chat:
        print(f"Telegram ayarı yok ({TELEGRAM_CONF})", file=sys.stderr)
        return False
    data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    try:
        with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=data, timeout=15) as r:
            return r.status == 200
    except Exception as e:
        print(f"Telegram gönderilemedi: {type(e).__name__}", file=sys.stderr)
        return False


def fingerprint(chains, env):
    items = sorted(f"{f.sev}|{f.code}|{f.title}" for f in env + [x for ch in chains for x in ch.findings] if f.sev >= LOW)
    return hashlib.sha256("\n".join(items).encode()).hexdigest()


# =====================================================================
# Ana akış
# =====================================================================

def analyze(chains, min_packets):
    for ch in chains:
        analyze_conflicts(ch)
        analyze_security(ch)
        analyze_structure(ch)
        analyze_performance(ch, min_packets)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="UFW / iptables kural seti denetimi: sıralama performansı, çakışma ve güvenlik analizi.")
    ap.add_argument("--mode", choices=("auto", "ufw", "iptables"), default="auto")
    ap.add_argument("--ufw-dir", default=UFW_DIR, help="user.rules / user6.rules dizini")
    ap.add_argument("--defaults", default=UFW_DEFAULTS, help="/etc/default/ufw yolu")
    ap.add_argument("--counters", help="iptables-save -c çıktısı (dosyadan; canlı okuma yerine)")
    ap.add_argument("--counters6", help="ip6tables-save -c çıktısı")
    ap.add_argument("--iptables-save", dest="dump", help="ham iptables-save dosyasını analiz et (UFW'siz sunucular)")
    ap.add_argument("--family", type=int, choices=(4, 6), help="--iptables-save için adres ailesi")
    ap.add_argument("--chain", action="append", help="yalnızca bu zincir(ler)i analiz et (iptables modu)")
    ap.add_argument("--sample", type=int, metavar="SN", help="sayaçları SN saniyelik pencerede ölç")
    ap.add_argument("--min-packets", type=int, default=MIN_PACKETS_DEFAULT,
                    help=f"sıralama önerisi için en az paket (varsayılan {MIN_PACKETS_DEFAULT})")
    ap.add_argument("--apply", action="store_true", help="önerilen (karar değiştirmeyen) sırayı uygula")
    ap.add_argument("--yes", action="store_true", help="--apply için onay sorma")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--quiet", "-q", action="store_true", help="rapor yazdırma")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--notify", action="store_true", help="özeti Telegram'a gönder")
    ap.add_argument("--notify-on-change", action="store_true", help="yalnızca bulgular değiştiyse gönder")
    ap.add_argument("--exit-code", action="store_true", help="kritik=2, uyarı=1 çıkış kodu döndür")
    args = ap.parse_args(argv)

    files = {}
    if args.dump or args.mode == "iptables":
        if args.dump:
            with open(args.dump, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        else:
            text = live_dump(args.family or 4)
            if text is None:
                sys.exit("iptables-save okunamadı (root gerekir).")
        chains, env, meta = load_generic(text, args.family, args.chain)
    else:
        dumps = {}
        for fam, path in ((4, args.counters), (6, args.counters6)):
            if path:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    dumps[fam] = fh.read()
            elif not (args.counters or args.counters6) and args.ufw_dir == UFW_DIR:
                dumps[fam] = live_dump(fam)
        if args.sample and not (args.counters or args.counters6):
            if not args.quiet:
                print(f"{args.sample} sn boyunca trafik ölçülüyor...", file=sys.stderr)
            time.sleep(args.sample)
            for fam in (4, 6):
                later = live_dump(fam)
                if later and dumps.get(fam):
                    dumps[fam] = subtract_dumps(later, dumps[fam])
        chains, files, env, meta = load_ufw(args.ufw_dir, dumps, args.defaults)
        if not chains and not files and args.mode == "auto":
            text = live_dump(4)
            if text:
                chains, env2, meta = load_generic(text, 4, args.chain)
                env += env2

    analyze(chains, args.min_packets)

    if not args.quiet:
        if args.json:
            print(render_json(chains, env, meta))
        else:
            print(render_text(chains, env, meta, sys.stdout.isatty() and not args.no_color, args.verbose))

    if args.notify or args.notify_on_change:
        send = True
        if args.notify_on_change:
            fp, path = fingerprint(chains, env), os.path.join(STATE_DIR, "audit.fingerprint")
            try:
                with open(path) as fh:
                    send = fh.read().strip() != fp
            except OSError:
                send = True
            if send:
                try:
                    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
                    with open(path, "w") as fh:
                        fh.write(fp)
                except OSError:
                    pass
        if send:
            send_telegram(render_telegram(chains, env, meta))

    if args.apply:
        if meta.get("mode") != "ufw":
            sys.exit("--apply yalnızca UFW modunda desteklenir.")
        if os.geteuid() != 0:
            sys.exit("--apply için root gerekir.")
        if args.ufw_dir != UFW_DIR or args.counters or args.counters6:
            sys.exit("--apply yalnızca canlı sistemde çalışır.")
        plan = build_plan(chains, files)
        if not plan:
            print("Uygulanacak sıralama değişikliği yok.")
        else:
            if not args.yes:
                ans = input("Önerilen sıra uygulansın mı? Kararlar değişmez, UFW yeniden yüklenir. [e/H] ")
                if ans.strip().lower() not in ("e", "evet", "y", "yes"):
                    print("Vazgeçildi.")
                    return 0
            if not apply_plan(plan, files, print):
                return 3

    if args.exit_code:
        worst = max([f.sev for f in env + [x for ch in chains for x in ch.findings]] or [INFO])
        return 2 if worst == HIGH else (1 if worst == MEDIUM else 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
