"""The match phase on server.dll (skipped when the GOG install or VC6 is absent): DllMain, Init and Exit
byte-match, the server thread is a draft, the full /DLL link resolves, the probe, promote and M1."""
from pathlib import Path

import pytest

from conftest import dcp, declare_vc6

SERVER = Path("C:/Program Files/GOG Galaxy/Games/The Guild Gold/server/server.dll")
TOOLCHAIN = Path("C:/Tools/MSVC600-SP5PP")

pytestmark = pytest.mark.skipif(not (SERVER.exists() and (TOOLCHAIN / "VC98" / "Bin" / "CL.EXE").exists()),
                                reason="server.dll or VC6 not installed")

HEAD = """/* dllmain: the dll's entry points and the server thread's handle and stop flag */
#include <windows.h>

unsigned long __cdecl _beginthread(void (__cdecl *start)(void *), unsigned stack_size, void *arglist);
void __cdecl ServerThread(void *arg);

int g_stopServer = 0;                   /* 0x10031270 */
unsigned long g_hServerThread = 0;      /* 0x11760c74 */
"""
FILES = {
    "src/dllmain.c": HEAD + "\n/* 0x10008cb0, the dll's entry point */\n"
                     "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n{\n    return TRUE;\n}\n"
                     "\n/* 0x10008cc0, starts the server thread */\nint __cdecl Init(void *arg)\n{\n"
                     "    g_hServerThread = _beginthread(ServerThread, 0, arg);\n    return g_hServerThread != (unsigned long)-1;\n}\n"
                     "\n/* 0x10008cf0, stops the server thread */\nvoid __cdecl Exit(void)\n{\n    if (g_hServerThread) {\n"
                     "        g_stopServer = 1;\n        do {\n            Sleep(10);\n        } while (g_stopServer);\n    }\n}\n",
    "src/server.c": "extern int g_stopServer;\n\n/* 0x10008d20, the server thread @rough */\n"
                    "void __cdecl ServerThread(void *arg)\n{\n    g_stopServer = 0;\n}\n",
}
DECL = ("0x10008cb0 boundary start by=guess tu=dllmain -- DllMain, Init and Exit\n"
        "0x10008d20 boundary end tu=dllmain -- the thread procedure begins the next unit\n"
        "0x10008d20 boundary start by=guess tu=server -- the server thread\n"
        "0x10009840 boundary end tu=server -- the server thread ends at 0x1000983f\n")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    from decompanion.init import init_project
    d = tmp_path_factory.mktemp("m3-server")
    init_project(d, SERVER, target_name="server")
    declare_vc6(d, ("LIBCMT",))
    (d / "decl" / "text.dcl").write_text("# code\n" + DECL, newline="\n")
    for rel, text in FILES.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(text, newline="\n")
    code, out = dcp(d, "build")
    assert code == 0, out
    return d


def test_byte_matches(server):
    code, out = dcp(server, "grade", "dllmain")
    for name in ("DllMain", "Init", "Exit"):
        line = next(l for l in out.splitlines() if f"name={name} " in l)
        assert "code=byte" in line and "readability=readable" in line, out
    code, out = dcp(server, "facts", "0x10008cb0..0x10008d20", "--kind", "symbol")
    assert "relocs=2/2" in out and "relocs=4/4" in out and "relocs=0/0" in out
    code, out = dcp(server, "next")
    assert "next=0x10008d20" in out and "name=ServerThread" in out and "section=draft" in out


def test_data_site(server):
    code, out = dcp(server, "facts", "0x10031270..0x10031274", "--kind", "symbol")
    assert "extent=site" in out and "name=g_stopServer" in out and "proven" in out


def test_link_and_check(server):
    code, out = dcp(server, "link")
    assert code == 0 and "ok=yes" in out and "unresolved=0" in out, out
    assert (server / "build" / "link" / "server" / "server.dll").exists()
    assert "Init @2" in (server / "build" / "link" / "server" / "server.def").read_text()
    code, out = dcp(server, "check")
    assert code == 0, out


def test_promote_and_m1(server):
    code, out = dcp(server, "promote")
    assert code == 0 and "functions=4" in out
    p = server / "src" / "dllmain.c"
    good = p.read_text()
    p.write_text(good.replace("!= (unsigned long)-1", "== 0"), newline="\n")
    try:
        code, out = dcp(server, "check")
        assert code == 1 and "M1" in out and "Init" in out
    finally:
        p.write_text(good, newline="\n")
    assert dcp(server, "check")[0] == 0


def test_probe(server):
    code, out = dcp(server, "toolchain", "probe")
    assert code == 0 and "anchors=3" in out and "matched=3/3" in out, out
    assert "indistinguishable" in out
    code, out = dcp(server, "toolchain")
    assert "probe  flag=/O2" in out
