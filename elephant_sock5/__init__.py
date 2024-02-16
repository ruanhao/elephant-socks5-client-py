import click
import logging
import websocket
from concurrent.futures import Future
from websocket._abnf import ABNF
from elephant_sock5.protocol import bytes_to_frame, hello, OP_CONTROL, OP_DATA, JRPCResponse, SessionRequest, Hello, Frame, TerminationRequest
from elephant_sock5.utils import LengthFieldBasedFrameDecoder, chunk_list, sneaky
from click import secho
import json
from py_netty import ServerBootstrap, ChannelHandlerAdapter, EventLoopGroup


logger = logging.getLogger(__name__)

URL = "ws://localhost:4443/elephant/ws"

decoder = LengthFieldBasedFrameDecoder()

responseFuture = {}

tunnel = None

clients = {}


def handle_frame(ws, frame_bytes):
    # print(socket_description(ws.sock.sock))
    frame = bytes_to_frame(frame_bytes)

    if frame.op_type == OP_CONTROL:
        payload = frame.payload
        jrpc = json.loads(payload.decode('utf-8'))
        jrpc_id = jrpc['id']
        assert jrpc_id
        method = None
        if jrpc_id in responseFuture:
            method, future = responseFuture.get(jrpc_id)
            del responseFuture[jrpc_id]
        else:                   # request
            pass
        if not method:
            method = jrpc.get('method', 'UNKNOWN')
        print(f"<={method}=", jrpc)
        if method == 'echo-request':
            ws.send(JRPCResponse.of(jrpc_id).to_frame_bytes(), ABNF.OPCODE_BINARY)
        elif method == 'termination-request':
            ws.send(JRPCResponse.of(jrpc_id).to_frame_bytes(), ABNF.OPCODE_BINARY)
            session_id = jrpc['params']['session-id']
            if session_id in clients:
                ctx = clients[session_id]
                ctx.close()
                del clients[session_id]
        elif method == 'session-request-response':
            future.set_result(jrpc)
        elif method == 'agent-hello-ack':
            pass

    elif frame.op_type == OP_DATA:
        # print("<=Data=", frame)
        session_id = frame.session_id
        payload = frame.payload
        if session_id in clients:
            ctx = clients[session_id]
            ctx.write(payload)


@sneaky()
def on_message(ws, bytes):
    frames = decoder.decode(bytes)
    for frame in frames:
        handle_frame(ws, frame)


def on_error(ws, error):
    if error and str(error):
        secho(f"[on_error] {error}", fg='red')


def on_close(ws, close_status_code, close_msg):
    if close_status_code is not None and close_msg is not None:
        logger.debug(f"[on_close] {close_status_code} {close_msg}")


@sneaky()
def on_open(ws):
    print("[on_open] Opened connection", ws)
    global tunnel
    tunnel = ws
    obj = Hello()
    responseFuture[obj.id] = ('agent-hello-ack', Future())
    ws.send(hello(obj), ABNF.OPCODE_BINARY)


@sneaky()
def start_client(url):
    ws = websocket.WebSocketApp(
        url,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    # ws.run_forever(dispatcher=rel, reconnect=5)
    ws.run_forever(reconnect=5)
    # rel.signal(2, rel.abort)
    # rel.dispatch()


class ProxyChannelHandler(ChannelHandlerAdapter):

    def __init__(self):
        self._session_id = None

    def exception_caught(self, ctx, exception):
        click.secho(f"[exception_caught] {exception}", fg='red')
        ctx.close()

    def channel_read(self, ctx, bytebuf):
        # print(f"[channel read] {len(bytebuf)} bytes")
        global tunnel
        if not self._session_id:
            # sr = SessionRequest.of('10.74.113.125', 8080)
            # sr = SessionRequest.of('localhost', 8080)
            sr = SessionRequest.sock5()
            future = Future()
            responseFuture[sr.id] = ('session-request-response', future)
            tunnel.send(sr.to_frame_bytes(), ABNF.OPCODE_BINARY)
            r = future.result()
            print("--->", r)
            self._session_id = r['result']['session-id']
            clients[self._session_id] = ctx

        for sub_bytebuf in chunk_list(bytebuf, 1024):
            data_frame = Frame(
                op_type=OP_DATA,
                session_id=self._session_id,
                payload=sub_bytebuf,
            )
            tunnel.send(data_frame.to_bytes(), ABNF.OPCODE_BINARY)

    def channel_inactive(self, ctx):
        if self._session_id:
            tr = TerminationRequest.of(self._session_id)
            responseFuture[tr.id] = ('termination-response', Future())
            tunnel.send(tr.to_frame_bytes(), ABNF.OPCODE_BINARY)
            if self._session_id in clients:
                del clients[self._session_id]
        pass


@click.command(short_help="Elephant SOCK5 client", context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--port', '-p', default=1080, help="Local port to bind", show_default=True, type=int)
@click.option('--server', '-s', 'url', help=f"Elephant tunnel server URL (like: {URL})", type=str, required=True)
def _cli(port, url):
    sb = ServerBootstrap(
        parant_group=EventLoopGroup(1, 'Acceptor'),
        child_group=EventLoopGroup(1, 'Worker'),
        child_handler_initializer=ProxyChannelHandler
    )

    sb.bind(port=port)
    print(f"Proxy server started at port {port}")
    start_client(url)


def _run():
    _cli()


if __name__ == '__main__':
    pass
