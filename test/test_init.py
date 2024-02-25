from unittest import TestCase
from elephant_sock5 import log_print, Tunnel
import io
from contextlib import redirect_stdout
from collections import namedtuple


def _catch_output(func, *args, **kwargs):
    f = io.StringIO()
    with redirect_stdout(f):
        func(*args, **kwargs)
    return f.getvalue()


class Test(TestCase):

    def test_check_connected(self):
        tunnel = Tunnel('')
        self.assertEqual(tunnel.check_connected(), False)
        tunnel._ever_active = True
        tunnel._ws = None
        self.assertEqual(tunnel.check_connected(), False)
        ws = namedtuple('WS', ['sock'])
        Sock = namedtuple('Sock', ['connected'])
        tunnel._ws = ws(sock=None)
        self.assertEqual(tunnel.check_connected(), False)
        tunnel._ws = ws(sock=Sock(connected=False))
        self.assertEqual(tunnel.check_connected(), False)
        tunnel._ws = ws(sock=Sock(connected=True))
        self.assertEqual(tunnel.check_connected(), True)

    def test_log_print(self):
        self.assertEqual(_catch_output(log_print, "hello", "world"), "hello world\n")
        self.assertEqual(_catch_output(log_print, "hello %s", "world"), "hello world\n")
        self.assertEqual(_catch_output(log_print, "hello %s", 123), "hello 123\n")
        self.assertEqual(_catch_output(log_print, "hello {}", "world"), "hello world\n")
        self.assertEqual(_catch_output(log_print, "hello {w}", w="world"), "hello world\n")
        self.assertEqual(_catch_output(log_print, "hello {w}", w=123, v=456), "hello 123\n")
