import unittest
from unittest.mock import Mock,patch
import preview


class TunnelTests(unittest.TestCase):
    def test_exit_between_poll_and_identity_read_needs_no_signal(self):
        child=Mock(pid=1234);child.poll.side_effect=[None,0]
        # A zombie keeps its PID/start time but Linux exposes an empty cmdline.
        with patch('pathlib.Path.read_bytes',return_value=b''):
            preview.stop_tunnel(child,b'our ssh argv')
        child.terminate.assert_not_called();child.kill.assert_not_called()

    def test_live_different_identity_still_refuses_every_signal(self):
        child=Mock(pid=1234);child.poll.return_value=None
        with patch('pathlib.Path.read_bytes',return_value=b'foreign process'):
            with self.assertRaises(RuntimeError):preview.stop_tunnel(child,b'our ssh argv')
        child.terminate.assert_not_called();child.kill.assert_not_called()

    def test_matching_live_tunnel_stops_and_waits(self):
        child=Mock(pid=1234);child.poll.return_value=None
        with patch('pathlib.Path.read_bytes',return_value=b'our ssh argv'):
            preview.stop_tunnel(child,b'our ssh argv')
        child.terminate.assert_called_once();child.wait.assert_called_once_with(10)
        child.kill.assert_not_called()
