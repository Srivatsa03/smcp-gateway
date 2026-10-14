`reference_tools.json` holds the tool definitions (name, description, input
schema) that seven MCP reference servers advertised on 2026-10-13, captured
with `tools/list`. They come from github.com/modelcontextprotocol/servers
(MIT License). `tests/test_scan.py` uses them to check that the description
scanner does not flag ordinary tools.
