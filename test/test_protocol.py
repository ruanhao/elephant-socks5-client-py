from unittest import TestCase
import json
from elephant_socks5.protocol import SessionRequest, OP_CONTROL, bytes_to_frame, Hello, TerminationRequest, Frame
from elephant_socks5.utils import LengthFieldBasedFrameDecoder
import struct


decoder = LengthFieldBasedFrameDecoder()


class Test(TestCase):

    def test_to_fram_bytes(self):
        format = '>BBHH'
        size = struct.calcsize(format)
        assert size == 6

        tr = TerminationRequest.of(123)
        self.assertEqual(tr.method, 'termination-request')
        self.assertEqual(tr.params['session-id'], 123)
        self.assertTrue(isinstance(tr.to_frame_bytes(), bytes))

        sr = SessionRequest.of('127.0.0.1', 1234)
        self.assertEqual(sr.method, 'session-request')
        self.assertEqual(sr.params['ip'], '127.0.0.1')
        self.assertEqual(sr.params['port'], 1234)
        self.assertEqual(sr.params['protocol'], 'TCP')
        self.assertFalse(sr.params.get('socks5', False))

        f = Frame(
            session_id=123,
            payload=b'hello'
        )
        self.assertEqual(f.version, 2)
        self.assertEqual(f.op_type, OP_CONTROL)
        self.assertEqual(f.session_id, 123)
        self.assertEqual(f.payload, b'hello')
        self.assertTrue(isinstance(f.to_bytes(), bytes))

    def test_jrpc_to_bytes(self):

        session_request = SessionRequest.of('117.127.137.147', 50000)
        # print("session_request: ", session_request)
        frame = session_request.to_frame()

        self.assertEqual(frame.version, 2)
        self.assertEqual(frame.session_id, 0)
        self.assertEqual(frame.op_type, OP_CONTROL)
        self.assertEqual(json.loads(frame.payload.decode('utf-8'))['method'], 'session-request')

        frame_bytes = session_request.to_frame_bytes()
        frame_bytes_0 = frame_bytes[:2]
        frame_bytes_1 = frame_bytes[2:6]
        frame_bytes_2 = frame_bytes[6:]

        frame0 = bytes_to_frame(frame_bytes_0 + frame_bytes_1 + frame_bytes_2)
        assert frame0 is not None
        assert frame0.session_id == 0
        assert frame0.op_type == OP_CONTROL

        message = decoder.decode(frame_bytes_0)
        assert message == []
        message = decoder.decode(frame_bytes_1)
        assert message == []
        message = decoder.decode(frame_bytes_2)
        assert message

        frame1 = bytes_to_frame(message[0])

        assert frame1 is not None
        assert frame1.session_id == 0
        assert frame1.op_type == OP_CONTROL

        messages = decoder.decode(frame_bytes * 100)
        assert len(messages) == 100
        messages = decoder.decode((frame_bytes * 100)[:-1])
        assert len(messages) == 99
        messages = decoder.decode((frame_bytes * 100)[-1:])
        assert len(messages) == 1
