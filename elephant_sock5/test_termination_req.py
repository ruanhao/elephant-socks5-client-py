import websocket
from websocket._abnf import ABNF
import rel
from elephant_sock5.protocol import *
from click import secho
import json

URL = "ws://localhost:4443/elephant/ws"

hello_jrpc_id = None
term_request_jrpc_id = None


def on_message(ws, bytes):
    global term_request_jrpc_id
    print("[on_message]", bytes)
    frame = get_frame_from_bytes(bytes)
    print(frame)
    jrpc = json.loads(frame.payload.decode('utf-8'))

    if jrpc['id'] == hello_jrpc_id:
        jrpc_obj = TerminationRequest.of(123)
        term_request_jrpc_id = jrpc_obj.id
        ws.send(control_bytes(jrpc_obj), ABNF.OPCODE_BINARY)
    else:
        assert jrpc['id'] == term_request_jrpc_id
        exit()


def on_error(ws, error):
    secho(f"[on_error] {error}", fg='red')


def on_close(ws, close_status_code, close_msg):
    print("[on_close]", close_status_code, close_msg)


def on_open(ws):
    global hello_jrpc_id
    print("[on_open] Opened connection", ws)
    jrpc_obj = Hello()
    hello_request = hello(jrpc_obj)
    hello_jrpc_id = jrpc_obj.id
    ws.send(hello_request, ABNF.OPCODE_BINARY)


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
