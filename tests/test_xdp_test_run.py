"""Offline tests for bench/xdp_test_run.py: the frame builder, the map-key conversion and the
bpf_attr layout that its BPF_PROG_TEST_RUN checks rest on. The checks themselves need root and
the kernel, and are not run here: nothing in this module loads a BPF program.
"""
import ctypes as ct
import os
import struct
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
import xdp_test_run as X

SRC = 0x0A090001                       # 10.9.0.1


class FrameTest(unittest.TestCase):
    def test_valid_syn(self):
        pkt = X.frame(SRC)
        self.assertEqual(len(pkt), 14 + 20 + 20)
        self.assertEqual(pkt[12:14], b"\x08\x00")                       # IPv4
        self.assertEqual(pkt[14], 0x45)                                 # version 4, ihl 5
        self.assertEqual(struct.unpack(">H", pkt[16:18])[0], 40)        # tot_len
        self.assertEqual(pkt[23], 6)                                    # TCP
        self.assertEqual(pkt[26:30], bytes([10, 9, 0, 1]))              # source
        self.assertEqual(pkt[30:34], bytes([10, 0, 0, 1]))              # destination
        self.assertEqual(struct.unpack(">HH", pkt[34:38]), (40000, 80))
        self.assertEqual(pkt[47] & 0x12, 0x02)                          # SYN without ACK
        self.assertEqual(struct.unpack(">H", pkt[48:50])[0], 64240)     # window

    def test_ihl_6_carries_its_options(self):
        pkt = X.frame(SRC, ihl=6, options=b"\x01\x01\x01\x01")
        self.assertEqual(len(pkt), 14 + 24 + 20)
        self.assertEqual(pkt[14], 0x46)
        self.assertEqual(pkt[34:38], b"\x01\x01\x01\x01")               # options, then TCP
        self.assertEqual(struct.unpack(">HH", pkt[38:42]), (40000, 80))
        self.assertEqual(struct.unpack(">H", pkt[16:18])[0], 44)

    def test_ihl_4_declares_less_than_it_carries(self):
        pkt = X.frame(SRC, ihl=4)
        self.assertEqual(pkt[14], 0x44)
        self.assertEqual(len(pkt), 14 + 20 + 20)                        # the bytes are still there

    def test_udp_and_other_ethertype(self):
        udp = X.frame(SRC, proto=17, sport=5353, dport=53, payload=b"x" * 10)
        self.assertEqual(len(udp), 14 + 20 + 8 + 10)
        self.assertEqual(udp[23], 17)
        self.assertEqual(struct.unpack(">H", udp[16:18])[0], 38)
        self.assertEqual(X.frame(SRC, ethertype=X.ETH_P_IPV6)[12:14], b"\x86\xdd")

    def test_map_key_is_the_address_bytes_read_little_endian(self):
        self.assertEqual(X.key_of(SRC), 0x0100090A)                     # bytes 0A 09 00 01 in memory
        self.assertEqual(X.key_of(0), 0)


class AttrLayoutTest(unittest.TestCase):
    def test_bpf_attr_test_member(self):
        # union bpf_attr, "test" member of BPF_PROG_TEST_RUN (uapi/linux/bpf.h)
        offsets = {name: getattr(X.TestAttr, name).offset for name, *_ in X.TestAttr._fields_}
        self.assertEqual(offsets["prog_fd"], 0)
        self.assertEqual(offsets["retval"], 4)
        self.assertEqual(offsets["data_size_in"], 8)
        self.assertEqual(offsets["data_in"], 16)
        self.assertEqual(offsets["repeat"], 32)
        self.assertEqual(offsets["duration"], 36)
        self.assertEqual(offsets["ctx_in"], 48)
        self.assertEqual(offsets["flags"], 64)
        self.assertEqual(offsets["batch_size"], 72)
        self.assertEqual(ct.sizeof(X.TestAttr), 80)


class ImportTest(unittest.TestCase):
    def test_importing_loads_no_bpf_machinery(self):
        # bcc is imported only when a program is loaded, so this module imports anywhere.
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import xdp_test_run; "
                "print('bcc' in sys.modules)")
        out = subprocess.run([sys.executable, "-I", "-c", code, os.path.join(REPO, "bench")],
                             capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "False")


if __name__ == "__main__":
    unittest.main()
