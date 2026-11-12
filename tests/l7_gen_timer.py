"""The hard exit of ml/l7_gen.py in a test process (T-074b). main() starts a daemon threading.Timer that calls _hard_exit (a group,
_hard_exit_group) HARD_EXIT_S after the run's end, and either one ends with os._exit(0): run in a test's own process, it would end the whole
suite with code 0 and no "Ran N tests" line, unless its write fails first. A test that calls l7_gen.main (or run_group, main_group) without
--plan keeps that timer inert (inert()); tests/test_l7_gen_hard_exit.py checks that none is left armed. ml/l7_gen.py is not changed."""
import os
import sys
import threading
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ML = os.path.join(os.path.dirname(HERE), "ml")
if ML not in sys.path:
    sys.path.insert(0, ML)
import l7_gen


class InertTimer:
    """threading.Timer as l7_gen.main uses it, never firing."""

    def __init__(self, *_a, **_k):
        self.daemon = True

    def start(self):
        pass

    def cancel(self):
        pass


def inert():
    """The hard-exit timer of l7_gen.main, inert for the duration of the context."""
    return mock.patch.object(l7_gen.threading, "Timer", InertTimer)


def hard_exits():
    """The functions a hard-exit timer of ml/l7_gen.py calls."""
    return tuple(f for f in (getattr(l7_gen, "_hard_exit", None), getattr(l7_gen, "_hard_exit_group", None)) if f is not None)


def live_hard_exits():
    """The armed threading.Timer threads of this process that would call l7_gen's hard exit."""
    targets = hard_exits()
    return [t for t in threading.enumerate()
            if isinstance(t, threading.Timer) and t.is_alive() and not t.finished.is_set() and getattr(t, "function", None) in targets]
