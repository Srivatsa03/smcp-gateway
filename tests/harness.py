"""Drive a Gateway in-process: no subprocesses, the bench server's logic plays upstream."""

import json

from smcp_gateway.client import check_server_hello
from smcp_gateway.gateway import Gateway
from smcp_gateway.protocol import APPROVAL, CALL, HELLO, SERVER_HELLO, make_hello, seal_call
from smcp_gateway.bench import upstream

INIT_RESULT = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
               "serverInfo": {"name": "acme-tools", "version": "1.4.2"}}


class Harness:
    """Drives a Gateway directly and plays the upstream server with bench.upstream."""

    def __init__(self, world, name="t-gw", **write_kwargs):
        self.world = world
        self.cfg = world.write(name, **write_kwargs)
        self.reg = world.registry(self.cfg)
        self.gw = Gateway.from_config(self.cfg, log=lambda m: None)
        self.forwarded: list[dict] = []
        self._n = 0

    def _id(self):
        self._n += 1
        return self._n

    def roundtrip(self, msg, server_result):
        up, down = self.gw.from_client(msg)
        if down:
            return down[0]
        self.forwarded.extend(up)
        return self.gw.from_server({"jsonrpc": "2.0", "id": msg["id"], "result": server_result})[0]

    def handshake(self, agent, tokens):
        hello, eph = make_hello(agent.id, agent.key, tokens)
        resp = self.roundtrip({"jsonrpc": "2.0", "id": self._id(), "method": "initialize",
                               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                          "clientInfo": {"name": "t", "version": "0"},
                                          "_meta": {HELLO: hello}}}, json.loads(json.dumps(INIT_RESULT)))
        if "error" in resp:
            return resp, None
        self.session_id, self.key, _ = check_server_hello(self.reg, hello, eph,
                                                          resp["result"]["_meta"][SERVER_HELLO])
        self.seq = 0
        return resp, self.session_id

    def list_tools(self, variant="clean"):
        return self.roundtrip({"jsonrpc": "2.0", "id": self._id(), "method": "tools/list", "params": {}},
                              {"tools": upstream.tools_for(variant)})["result"]["tools"]

    def call(self, name, args, envelope=None, approval=None, **ctx):
        if envelope is None:
            self.seq += 1
            envelope = seal_call(self.key, self.session_id, self.seq, name, args, approval=approval, **ctx)
        text, err = upstream.call_tool(name, args)
        meta = {CALL: envelope}
        if approval is not None:
            meta[APPROVAL] = approval
        resp = self.roundtrip({"jsonrpc": "2.0", "id": self._id(), "method": "tools/call",
                               "params": {"name": name, "arguments": args, "_meta": meta}},
                              {"content": [{"type": "text", "text": text}], "isError": err})
        return resp, envelope




def text(resp):
    return resp["result"]["content"][0]["text"]
