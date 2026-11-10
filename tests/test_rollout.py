import unittest
from unittest.mock import patch
import rollout


class RolloutTests(unittest.TestCase):
    def test_repeated_web_refresh_keeps_the_authoritative_initial_stage(self):
        stage='a'*10;web='b'*10
        self.assertEqual(stage,rollout.stage_parent({'success':True,'phase':'private-services-staged'},stage))
        self.assertEqual(stage,rollout.stage_parent({'success':True,'phase':'upgraded'},stage))
        self.assertEqual(stage,rollout.stage_parent({'success':True,'phase':'web-refreshed','previous_stage':stage},web))
        for bad in ({'success':False,'phase':'web-refreshed','previous_stage':stage},
                    {'success':True,'phase':'unknown'},
                    {'success':True,'phase':'web-refreshed','previous_stage':'../escape'}):
            with self.assertRaises(ValueError):rollout.stage_parent(bad,web)

    def test_stage_requires_real_complete_qualification(self):
        sha='a'*64
        template={'sha256':sha,'keyless':True,'cold_identity':True}
        qa={'success':True,'qualified':True,'sha256':sha,'architecture':'amd64',
            'key_isolation':True,'ssh_positive_negative':True,'results':[]}
        for firmware in ('bios','uefi'):
            qa['results'].append({'firmware':firmware,**{name:True for name in
                ('success','clean_shutdown','wrong_key_rejected','password_rejected','ssh_positive')}})
        sources={'success':True,'metadata_only':False,'includes_built_using':True,'template_sha256':sha,
                 'sources':[{'name':'linux','version':'1'}],'files':{'example':{}}}
        inventory={'template_sha256':sha,'includes_built_using':True,'sources':[['linux','1']]}
        rollout.validate(qa,template,sources,inventory,'same','same')
        for key,value in (('metadata_only',True),('includes_built_using',False),('success',False),('template_sha256','b'*64)):
            bad={**sources,key:value}
            with self.assertRaises(ValueError):rollout.validate(qa,template,bad,inventory,'same','same')
        with self.assertRaises(ValueError):rollout.validate(qa,template,sources,inventory,'old','new')

    def test_no_local_deployment_or_image_read(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch('rollout.bundle') as bundle:
            with self.assertRaises(RuntimeError):rollout.stage('a'*10,'b'*10,'c'*10,'d'*10,'x')
        bundle.assert_not_called()
