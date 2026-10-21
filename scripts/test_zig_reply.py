import importlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

FILES = Path(__file__).resolve().parents[1] / 'ansible/roles/vulnerability_incidents/files'
sys.path.insert(0,str(FILES))
zig_reply = importlib.import_module('zig_reply')


class ZigReplyTests(unittest.TestCase):
    def reply(self):
        return {'id':'incident_reply','thread_root':'$root','reply_to':'$request',
                'context':{'kind':'assessment','request':'can you look into this?',
                           'assessment':{'summary':'retained evidence'}}}

    def test_zig_owns_the_response_and_delivery_preserves_it_unchanged(self):
        client=mock.Mock()
        client.call.side_effect=[{'reply':self.reply()},{'status':'saved'}]
        responder=mock.Mock(return_value='This is exactly what Zig chose to say.\n\nWith its own layout.')
        matrix=mock.Mock()
        matrix.send.return_value='$answer'

        self.assertTrue(zig_reply.deliver_one(client,responder,matrix))

        responder.assert_called_once_with(self.reply())
        matrix.send.assert_called_once_with(responder.return_value,'incident_reply','$root','$request')
        client.call.assert_called_with('reply_delivered',reply='incident_reply',event_id='$answer')

    def test_no_pending_evidence_does_not_invoke_zig_or_matrix(self):
        client=mock.Mock()
        client.call.return_value={'reply':None}
        responder=mock.Mock()
        matrix=mock.Mock()
        self.assertFalse(zig_reply.deliver_one(client,responder,matrix))
        responder.assert_not_called()
        matrix.send.assert_not_called()

    @mock.patch.object(zig_reply.request,'urlopen')
    def test_matrix_delivery_replies_to_the_original_request(self,urlopen):
        urlopen.return_value.__enter__.return_value=io.BytesIO(b'{"event_id":"$answer"}')
        sender=zig_reply.MatrixSender('https://matrix.invalid','!room','secret')
        self.assertEqual(sender.send('Zig response','reply-id','$root','$request'),'$answer')
        sent=json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(sent['body'],'Zig response')
        self.assertEqual(sent['m.relates_to']['event_id'],'$root')
        self.assertEqual(sent['m.relates_to']['m.in_reply_to']['event_id'],'$request')


if __name__=='__main__':
    unittest.main()
