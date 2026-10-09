#!/usr/bin/env python3
"""ufw_audit.py testleri:  python3 -m unittest discover -s tests -v"""
import itertools
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ufw_audit as A  # noqa: E402

HEADER = """*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
:ufw-user-limit - [0:0]
:ufw-user-limit-accept - [0:0]
### RULES ###
"""
FOOTER = """
### END RULES ###

### LOGGING ###
### END LOGGING ###
COMMIT
"""


def rule(action, proto="any", dport="any", src="0.0.0.0/0", chain="ufw-user-input"):
    """ufw'nin user.rules'a yazdığı biçimde bir tuple bloğu üretir."""
    tup = f"### tuple ### {action} {proto} {dport} 0.0.0.0/0 any {src} in"
    s = "" if src == "0.0.0.0/0" else f" -s {src}"
    protos = [proto] if proto != "any" else (["tcp", "udp"] if dport != "any" else ["all"])
    lines = []
    for p in protos:
        base = f"-A {chain} -p {p}" + (f" --dport {dport}" if dport != "any" else "") + s
        if action == "limit":
            lines += [base + " -m conntrack --ctstate NEW -m recent --set",
                      base + " -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 -j ufw-user-limit",
                      base + " -j ufw-user-limit-accept"]
        else:
            lines.append(base + " -j " + {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT"}[action])
    return tup + "\n" + "\n".join(lines)


def user_rules(blocks):
    return HEADER + "".join("\n" + b + "\n" for b in blocks) + FOOTER


def counters(blocks, hits, entered):
    """Bloklara karşılık gelen iptables-save -c çıktısı. hits: blok başına sonlanan paket."""
    out = ["*filter", ":ufw-before-input - [0:0]", ":ufw-user-input - [0:0]",
           f"[{entered}:0] -A ufw-before-input -j ufw-user-input"]
    for b, h in zip(blocks, hits):
        lines = b.split("\n")[1:]
        for k, ln in enumerate(lines):
            n = h if k == len(lines) - 1 else 0     # isabeti son (sonlandıran) satıra yaz
            out.append(f"[{n}:0] {ln}")
    return "\n".join(out + ["COMMIT"]) + "\n"


def audit(blocks, hits=None, entered=None, policy="DROP", min_packets=1000):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "user.rules"), "w") as fh:
        fh.write(user_rules(blocks))
    with open(os.path.join(d, "ufw.conf"), "w") as fh:
        fh.write("ENABLED=yes\nLOGLEVEL=low\n")
    defaults = os.path.join(d, "defaults")
    with open(defaults, "w") as fh:
        fh.write(f'DEFAULT_INPUT_POLICY="{policy}"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="DROP"\n')
    dumps = {}
    if hits is not None:
        dumps[4] = counters(blocks, hits, entered if entered is not None else sum(hits))
    chains, files, env, meta = A.load_ufw(d, dumps, defaults)
    A.analyze(chains, min_packets)
    return chains, files, env


def codes(chains, env=()):
    return [f.code for f in list(env) + [x for ch in chains for x in ch.findings]]


class Geometry(unittest.TestCase):
    def test_subtract_partitions_box(self):
        rnd = random.Random(1)
        for _ in range(300):
            b = tuple(tuple(sorted((rnd.randint(0, 6), rnd.randint(0, 6)))) for _ in range(3))
            a = tuple(tuple(sorted((rnd.randint(0, 6), rnd.randint(0, 6)))) for _ in range(3))
            if not A.intersects(a, b):
                continue
            pieces = A.subtract(b, a)
            pts = lambda box: set(itertools.product(*[range(lo, hi + 1) for lo, hi in box]))
            got = set()
            for p in pieces:
                self.assertFalse(got & pts(p), "parçalar ayrık olmalı")
                got |= pts(p)
            self.assertEqual(got, pts(b) - pts(a))

    def test_union_coverage(self):
        full = [((0, 9),)]
        self.assertEqual(A.remainder(full, [((0, 4),), ((5, 9),)]), [])
        self.assertEqual(A.remainder(full, [((0, 4),), ((6, 9),)]), [((5, 5),)])


class Parser(unittest.TestCase):
    def test_iptables_save_line(self):
        ln = A.parse_rule_line('[12:720] -A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -j ACCEPT', 4)
        self.assertEqual((ln.chain, ln.target, ln.pkts, ln.kind, ln.opaque), ("INPUT", "ACCEPT", 12, "allow", False))
        proto, src, _, _, dp, _, _, _ = ln.atoms[0]
        self.assertEqual((proto, dp), ((6, 6), (22, 22)))
        self.assertEqual(src, (10 << 24, (10 << 24) + 2 ** 24 - 1))

    def test_multiport_and_state(self):
        ln = A.parse_rule_line('-A INPUT -p tcp -m multiport --dports 80,443,8000:8100 -m conntrack --ctstate NEW -j ACCEPT', 4)
        self.assertFalse(ln.opaque)
        self.assertEqual(sorted(a[4] for a in ln.atoms), [(80, 80), (443, 443), (8000, 8100)])
        self.assertEqual({a[5] for a in ln.atoms}, {(0, 0)})

    def test_unmodelled_match_is_opaque(self):
        for raw in ('-A INPUT -p tcp --dport 22 -m recent --set',
                    '-A INPUT ! -s 10.0.0.1/32 -j DROP',
                    '-A INPUT -p icmp --icmp-type 8 -j ACCEPT',
                    '-A INPUT -m set --match-set bad src -j DROP'):
            self.assertTrue(A.parse_rule_line(raw, 4).opaque, raw)

    def test_target_options_do_not_make_opaque(self):
        ln = A.parse_rule_line('-A INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset', 4)
        self.assertFalse(ln.opaque)
        ln = A.parse_rule_line("-A ufw-user-input -p tcp --dport 22 -j ACCEPT -m comment --comment 'dapp_OpenSSH'", 4)
        self.assertFalse(ln.opaque)

    def test_ufw_file_roundtrip(self):
        blocks = [rule("allow", "tcp", "22"), rule("limit", "tcp", "2222"), rule("deny", src="1.2.3.4")]
        uf = A.UfwFile("x", user_rules(blocks))
        self.assertTrue(uf.ok)
        self.assertEqual(uf.blocks, blocks)
        self.assertEqual(uf.render(uf.blocks), uf.text)


class Solver(unittest.TestCase):
    def brute(self, w, p, prec):
        best = None
        for perm in itertools.permutations(range(len(w))):
            if A.order_is_safe(perm, prec):
                c = A.chain_cost(perm, w, p)
                best = c if best is None else min(best, c)
        return best

    def test_exact_matches_brute_force(self):
        rnd = random.Random(7)
        for _ in range(250):
            n = rnd.randint(1, 7)
            w = [rnd.choice([0, 0, 1, 5, 50, 500]) for _ in range(n)]
            p = [rnd.randint(1, 3) for _ in range(n)]
            prec = [sum(1 << i for i in range(j) if rnd.random() < 0.3) for j in range(n)]
            order, exact = A.solve_order(w, p, prec)
            self.assertTrue(exact)
            self.assertTrue(A.order_is_safe(order, prec))
            self.assertEqual(sorted(order), list(range(n)))
            self.assertEqual(A.chain_cost(order, w, p), self.brute(w, p, prec))

    def test_heuristic_is_safe_and_never_worse(self):
        rnd = random.Random(3)
        for _ in range(100):
            n = rnd.randint(2, 40)
            w = [rnd.choice([0, 1, 10, 1000]) for _ in range(n)]
            p = [rnd.randint(1, 3) for _ in range(n)]
            prec = [sum(1 << i for i in range(j) if rnd.random() < 0.1) for j in range(n)]
            order = A._heuristic(w, p, prec)
            self.assertTrue(A.order_is_safe(order, prec))
            self.assertLessEqual(A.chain_cost(order, w, p), A.chain_cost(range(n), w, p))

    def test_heuristic_close_to_exact(self):
        rnd = random.Random(11)
        for _ in range(60):
            n = rnd.randint(3, 10)
            w = [rnd.choice([0, 1, 10, 1000]) for _ in range(n)]
            p = [rnd.randint(1, 3) for _ in range(n)]
            prec = [sum(1 << i for i in range(j) if rnd.random() < 0.25) for j in range(n)]
            ex = A._exact(w, p, prec, list(range(n)))
            h = A._heuristic(w, p, prec)
            self.assertLessEqual(A.chain_cost(h, w, p), 2 * max(1, A.chain_cost(ex, w, p)))

    def test_ties_keep_current_order(self):
        order, _ = A.solve_order([5, 5, 5], [1, 1, 1], [0, 0, 0])
        self.assertEqual(order, [0, 1, 2])

    def test_large_ruleset_finishes(self):
        rnd = random.Random(5)
        n = 300
        w = [rnd.choice([0, 0, 0, 3, 90]) for _ in range(n)]
        prec = [sum(1 << i for i in range(max(0, j - 8), j) if rnd.random() < 0.2) for j in range(n)]
        order, _ = A.solve_order(w, [1] * n, prec)
        self.assertTrue(A.order_is_safe(order, prec))
        self.assertLessEqual(A.chain_cost(order, w, [1] * n), A.chain_cost(range(n), w, [1] * n))


class SimulatorScenarios(unittest.TestCase):
    """Dersteki simülatörün senaryoları: hacmi büyük olan üste çıkmalı, kontrol sayıları aynı olmalı."""

    def check(self, blocks, hits, expected_order, now, best):
        chains, _, _ = audit(blocks, hits)
        pf = chains[0].perf
        self.assertTrue(pf["exact"])
        self.assertEqual(pf["cost_now"], now)
        self.assertEqual(pf["cost_opt"], best)
        self.assertEqual(pf["order"], expected_order)

    def test_level1_school_network(self):
        # Kötü sıra: admin(22) → web(80) → okul dışı DENY. En iyi: dış → web → admin (1.210.000 kontrol)
        blocks = [rule("allow", "tcp", "22", "10.1.0.0/24"), rule("allow", "tcp", "80", "10.0.0.0/8"),
                  rule("deny", src="203.0.113.0/24")]
        self.check(blocks, [10_000, 190_000, 800_000], [2, 1, 0], 10_000 + 380_000 + 2_400_000, 1_210_000)

    def test_level2_ddos(self):
        blocks = [rule("allow", "tcp", "443", "10.0.0.0/8"), rule("deny", src="198.51.100.0/24")]
        self.check(blocks, [50_000, 950_000], [1, 0], 50_000 + 1_900_000, 950_000 + 100_000)

    def test_level3_allow_only(self):
        blocks = [rule("allow", "tcp", "25"), rule("allow", "tcp", "443"), rule("allow", "tcp", "5432")]
        self.check(blocks, [100_000, 700_000, 200_000], [1, 2, 0], 100_000 + 1_400_000 + 600_000, 700_000 + 400_000 + 300_000)

    def test_level4_catch_all_stays_last(self):
        # 'Diğer her şeyi reddet' tüm kurallarla kesişir: hacmi ne olursa olsun sonda kalmalı
        blocks = [rule("allow", "tcp", "3306"), rule("deny", src="192.0.2.0/24"), rule("allow", "tcp", "1883"),
                  rule("allow", "tcp", "9000"), rule("deny")]
        chains, _, _ = audit(blocks, [150_000, 300_000, 500_000, 50_000, 900_000])
        order = chains[0].perf["order"]
        self.assertEqual(order[-1], 4)
        # 192.0.2.0/24 DENY bütün portları kapsar → ALLOW kurallarıyla kesişir, onların önüne/arkasına geçemez
        self.assertLess(order.index(0), order.index(1))
        self.assertTrue(A.order_is_safe(order, chains[0].prec))

    def test_no_recommendation_without_enough_traffic(self):
        blocks = [rule("allow", "tcp", "22"), rule("allow", "tcp", "80")]
        chains, _, _ = audit(blocks, [1, 50])
        self.assertIn("AZ-ORNEK", codes(chains))
        self.assertNotIn("SIRALAMA", codes(chains))
        self.assertEqual(A.build_plan(chains, {}), {})

    def test_default_policy_traffic_counts_full_chain(self):
        blocks = [rule("allow", "tcp", "22"), rule("allow", "tcp", "80")]
        chains, _, _ = audit(blocks, [1000, 1000], entered=12_000)
        pf = chains[0].perf
        self.assertEqual(pf["miss"], 10_000)
        self.assertEqual(pf["cost_now"], 1000 + 2000 + 10_000 * 2)


class Semantics(unittest.TestCase):
    """Önerilen sıra hiçbir paketin kararını değiştirmemeli (rastgele paketlerle doğrulama)."""

    def decide(self, groups, order, pkt):
        for j in order:
            g = groups[j]
            for ln in g.lines:
                if ln.kind in ("allow", "deny") and any(
                        a[0][0] <= pkt[0] <= a[0][1] and a[1][0] <= pkt[1] <= a[1][1] and a[4][0] <= pkt[2] <= a[4][1]
                        for a in ln.atoms):
                    return j
        return None

    def test_first_matching_rule_is_invariant(self):
        rnd = random.Random(42)
        srcs = ["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.3", "203.0.113.0/24", "203.0.113.7"]
        for _ in range(60):
            n = rnd.randint(3, 9)
            blocks = [rule(rnd.choice(["allow", "deny"]), rnd.choice(["tcp", "udp", "any"]),
                           rnd.choice(["22", "80", "443", "any"]), rnd.choice(srcs)) for _ in range(n)]
            hits = [rnd.choice([0, 10, 1000, 100_000]) for _ in range(n)]
            chains, _, _ = audit(blocks, hits)
            ch = chains[0]
            order = ch.perf["order"]
            self.assertTrue(A.order_is_safe(order, ch.prec))
            for _ in range(300):
                ip = rnd.choice([(10 << 24) + (1 << 16) + (2 << 8) + 3, (10 << 24) + 5, (203 << 24) + (113 << 8) + 7,
                                 (203 << 24) + (113 << 8) + 9, 0x08080808])
                pkt = (rnd.choice([6, 17, 1]), ip, rnd.choice([22, 80, 443, 9999]))
                self.assertEqual(self.decide(ch.groups, range(n), pkt), self.decide(ch.groups, order, pkt))


class Conflicts(unittest.TestCase):
    def test_deny_after_broad_allow_is_partly_ineffective(self):
        # En sık yapılan hata: 'ufw allow 22' sonrası 'ufw deny from <IP>'
        chains, _, _ = audit([rule("allow", "tcp", "22"), rule("deny", src="203.0.113.7")])
        f = next(x for x in chains[0].findings if x.code == "KISMI-ETKISIZ")
        self.assertEqual(f.sev, A.MEDIUM)
        self.assertIn("sudo ufw delete 2", f.fix)
        self.assertIn("sudo ufw insert 1 deny from 203.0.113.7 to any", f.fix)

    def test_fully_shadowed_deny_is_critical(self):
        chains, _, _ = audit([rule("allow", "tcp", "22"), rule("deny", "tcp", "22", "203.0.113.7")])
        f = next(x for x in chains[0].findings if x.code == "GOLGELEME")
        self.assertEqual(f.sev, A.HIGH)

    def test_shadowing_by_union_of_rules(self):
        chains, _, _ = audit([rule("allow", "tcp", "80", "10.0.0.0/9"), rule("allow", "tcp", "80", "10.128.0.0/9"),
                              rule("deny", "tcp", "80", "10.0.0.0/8")])
        self.assertIn("GOLGELEME", codes(chains))

    def test_duplicate_and_subset_are_redundant(self):
        chains, _, _ = audit([rule("allow", "tcp", "22"), rule("allow", "tcp", "22", "10.0.0.5")])
        self.assertIn("GEREKSIZ", codes(chains))
        chains, _, _ = audit([rule("allow", "tcp", "22", "10.0.0.5"), rule("allow", "tcp", "22")])
        self.assertIn("GEREKSIZ", codes(chains))

    def test_exception_before_general_rule_is_fine(self):
        chains, _, _ = audit([rule("deny", "tcp", "22", "203.0.113.7"), rule("allow", "tcp", "22")])
        cs = codes(chains)
        self.assertIn("ISTISNA", cs)
        for bad in ("GOLGELEME", "KISMI-ETKISIZ", "GEREKSIZ"):
            self.assertNotIn(bad, cs)

    def test_intervening_deny_keeps_specific_allow(self):
        chains, _, _ = audit([rule("allow", "tcp", "22", "10.0.0.5"), rule("deny", "tcp", "22", "10.0.0.0/8"),
                              rule("allow", "tcp", "22")])
        self.assertNotIn("GEREKSIZ", codes(chains))

    def test_limit_shadowed_by_allow(self):
        chains, _, _ = audit([rule("allow", "tcp", "22"), rule("limit", "tcp", "22")])
        f = next(x for x in chains[0].findings if x.code == "GOLGELEME")
        self.assertEqual(f.sev, A.MEDIUM)

    def test_disjoint_rules_are_clean(self):
        chains, _, _ = audit([rule("limit", "tcp", "22"), rule("allow", "tcp", "443"), rule("deny", "udp", "161")])
        self.assertEqual([c for c in codes(chains) if c not in ("ISTISNA",)], [])


class Security(unittest.TestCase):
    def test_world_open_database(self):
        chains, _, _ = audit([rule("allow", "tcp", "3306")])
        f = next(x for x in chains[0].findings if x.code == "HASSAS-PORT")
        self.assertEqual(f.sev, A.HIGH)

    def test_source_restricted_database_is_fine(self):
        chains, _, _ = audit([rule("allow", "tcp", "3306", "10.0.0.0/8")])
        self.assertNotIn("HASSAS-PORT", codes(chains))

    def test_ssh_limit_is_fine_plain_allow_is_flagged(self):
        self.assertIn("SSH-ACIK", codes(audit([rule("allow", "tcp", "22")])[0]))
        self.assertNotIn("SSH-ACIK", codes(audit([rule("limit", "tcp", "22")])[0]))

    def test_allow_everything(self):
        chains, _, _ = audit([rule("allow"), rule("deny", src="203.0.113.7")])
        cs = codes(chains)
        self.assertIn("HER-SEYE-IZIN", cs)
        self.assertIn("GOLGELEME", cs)

    def test_default_accept_policy(self):
        _, _, env = audit([rule("allow", "tcp", "443")], policy="ACCEPT")
        self.assertIn("POLITIKA-ACIK", [f.code for f in env])

    def test_cidr_merge_suggestion(self):
        chains, _, _ = audit([rule("deny", src="203.0.113.0/25"), rule("deny", src="203.0.113.128/25")])
        self.assertIn("BIRLESTIR", codes(chains))


class Plan(unittest.TestCase):
    def test_plan_reorders_blocks_and_keeps_file_valid(self):
        blocks = [rule("allow", "tcp", "22", "10.1.0.0/24"), rule("allow", "tcp", "80", "10.0.0.0/8"),
                  rule("deny", src="203.0.113.0/24")]
        chains, files, _ = audit(blocks, [10_000, 190_000, 800_000])
        plan = A.build_plan(chains, files)
        self.assertEqual(plan[4], [blocks[2], blocks[1], blocks[0]])
        new = A.UfwFile("x", files[4].render(plan[4]))
        self.assertTrue(new.ok)
        self.assertEqual(sorted(new.blocks), sorted(blocks))
        self.assertTrue(new.text.startswith(HEADER) and new.text.endswith(FOOTER))

    def test_no_plan_when_already_optimal(self):
        blocks = [rule("deny", src="203.0.113.0/24"), rule("allow", "tcp", "80", "10.0.0.0/8")]
        chains, files, _ = audit(blocks, [800_000, 190_000])
        self.assertEqual(A.build_plan(chains, files), {})


class GenericIptables(unittest.TestCase):
    DUMP = """# Generated by iptables-save
*filter
:INPUT DROP [500:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
[10:0] -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
[20:0] -A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT
[5:0] -A INPUT -s 203.0.113.7/32 -j DROP
[90000:0] -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
[0:0] -A INPUT -s 10.0.0.5/32 -p tcp -m tcp --dport 443 -j DROP
[900000:0] -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
COMMIT
"""

    def test_plain_iptables_ruleset(self):
        chains, env, meta = A.load_generic(self.DUMP, None, None)
        A.analyze(chains, 1000)
        ch = next(c for c in chains if c.name == "INPUT")
        cs = codes([ch], env)
        self.assertEqual(meta["mode"], "iptables")
        self.assertIn("HIZLI-YOL", cs)          # ESTABLISHED kuralı sonda
        self.assertIn("GOLGELEME", cs)          # 10.0.0.5:443 DROP, önceki 443 ACCEPT yüzünden ölü
        self.assertIn("KISMI-ETKISIZ", cs)      # 203.0.113.7 DROP, 22/3306 için etkisiz
        self.assertIn("HASSAS-PORT", cs)
        self.assertEqual(ch.perf["miss"], 500)
        self.assertTrue(A.order_is_safe(ch.perf["order"], ch.prec))
        self.assertLess(ch.perf["cost_opt"], ch.perf["cost_now"])

    def test_cli_on_dump_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rules", delete=False) as fh:
            fh.write(self.DUMP)
        self.assertEqual(A.main(["--iptables-save", fh.name, "--quiet"]), 0)
        self.assertEqual(A.main(["--iptables-save", fh.name, "--quiet", "--exit-code"]), 2)


if __name__ == "__main__":
    unittest.main()
