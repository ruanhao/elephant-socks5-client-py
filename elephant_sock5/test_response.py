import websocket
from websocket._abnf import ABNF
import rel
from elephant_sock5.protocol import bytes_to_frame, hello, OP_CONTROL, OP_DATA, JRPCResponse
from elephant_sock5.utils import LengthFieldBasedFrameDecoder
from click import secho
from qqutils import sneaky, socket_description
import json

URL = "ws://localhost:4443/elephant/ws"

decoder = LengthFieldBasedFrameDecoder()


def handle_frame(ws, frame_bytes):
    print(socket_description(ws.sock.sock))
    frame = bytes_to_frame(frame_bytes)

    if frame.op_type == OP_CONTROL:
        print("<=Control=", frame)
        payload = frame.payload
        jrpc = json.loads(payload.decode('utf-8'))
        jrpc_id = jrpc['id']
        assert jrpc_id
        method = jrpc.get('method', 'agent-hello-ack')
        print(f"  <={method}=", jrpc)
        if method == 'echo-request' or method == 'termination-request':
            ws.send(JRPCResponse.of(jrpc_id).to_frame_bytes(), ABNF.OPCODE_BINARY)
        elif method == 'agent-hello-ack':
            pass
        else:
            print(f"  <=Unknown method={method}", jrpc)

    elif frame.op_type == OP_DATA:
        print("<=Data=", frame)


@sneaky()
def on_message(ws, bytes):
    print("[on_message]", bytes)
    frames = decoder.decode(bytes)
    for frame in frames:
        handle_frame(ws, frame)


def on_error(ws, error):
    secho(f"[on_error] {error}", fg='red')


def on_close(ws, close_status_code, close_msg):
    print("[on_close]", close_status_code, close_msg)


@sneaky()
def on_open(ws):
    print("[on_open] Opened connection", ws)
    ws.send(hello(), ABNF.OPCODE_BINARY)


def test():
    websocket.enableTrace(True)
    ws = websocket.WebSocketApp(
        URL,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    ws.run_forever(dispatcher=rel, reconnect=5)
    rel.signal(2, rel.abort)
    rel.dispatch()

if __name__ == '__main__':
    test()
