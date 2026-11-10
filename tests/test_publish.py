import unittest
from unittest.mock import patch
import publish


class PublishTests(unittest.TestCase):
    def test_only_project_route_and_log_exclusion_change(self):
        old='Header test\n    ProxyPass /wsmain wss://127.0.0.1:7796/wsmain\n    ProxyPass / https://127.0.0.1:7796/\n    ProxyPassReverse / https://127.0.0.1:7796/\n    CustomLog ${APACHE_LOG_DIR}/eorls.com.ssl.access.log combined\nFooter test\n'
        new=publish.patch_vhost(old)
        self.assertIn('Include /etc/debrescuestick/apache.conf',new)
        self.assertIn('ProxyPass /wsmain wss://127.0.0.1:7796/wsmain',new)
        self.assertEqual(new.replace('    Include /etc/debrescuestick/apache.conf\n','').replace(' combined env=!drs_private\n',' combined\n'),old)
        for wrong in (old.replace('7796/','7797/'),old+old,new):
            with self.assertRaises(ValueError):publish.patch_vhost(wrong)

    def test_no_local_cutover(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch('publish.bundle') as bundle:
            with self.assertRaises(RuntimeError):publish.run('a'*10,'b'*10,'c'*10,'d'*10,'x','y')
        bundle.assert_not_called()
