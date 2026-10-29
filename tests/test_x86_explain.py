"""The x86 hunk explanation (isa/x86.py X86.explain) for stores moved across a push: esp offsets are compared as
they were at the hunk's start (esp_normalised)."""
from decompanion.isa.x86 import X86, esp_normalised


def test_esp_normalised():
    lines = ["mov dword ptr [esp + 0x10], eax", "push edx", "mov dword ptr [esp + 0x14], eax", "sub esp, 8",
             "mov dword ptr [esp + 0x1c], eax", "pop ecx", "mov eax, dword ptr [esp]"]
    assert esp_normalised(lines) == ["mov dword ptr [esp + 0x10], eax", "push edx", "mov dword ptr [esp + 0x10], eax",
                                     "sub esp, 8", "mov dword ptr [esp + 0x10], eax", "pop ecx", "mov eax, dword ptr [esp - 0x8]"]


def test_store_moved_across_a_push():
    """ai_CurseWindow of GildeGold.exe: ours stores before the push, the original after it; the word store is
    the same slot (0xa4 before = 0xa8 after the push), the dword store another one (0xd0 on both sides)."""
    ours = ["mov word ptr [esp + 0xa4], ax", "mov ecx, dword ptr [ebp + 4]", "lea edx, [esp + 0x70]",
            "mov dword ptr [esp + 0xd0], ecx", "push edx"]
    orig = ["mov ecx, dword ptr [ebp + 4]", "lea edx, [esp + 0x70]", "push edx",
            "mov word ptr [esp + 0xa8], ax", "mov dword ptr [esp + 0xd0], ecx"]
    cls, why = X86().explain(ours, orig, ours + orig)
    assert cls == "slots" and "across a push" in why
    same = ["mov ecx, dword ptr [ebp + 4]", "lea edx, [esp + 0x70]", "push edx",
            "mov word ptr [esp + 0xa8], ax", "mov dword ptr [esp + 0xd4], ecx"]
    cls, why = X86().explain(ours, same, ours + same)
    assert cls == "order"                                   # only the order differs once the push is accounted for
