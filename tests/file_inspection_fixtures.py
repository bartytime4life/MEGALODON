"""Small synthetic executable headers; no runnable program bodies or malware."""
import struct


def elf(*, writable=False):
    identity = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    header = identity + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    segment = struct.pack('<IIQQQQQQ', 1, 7 if writable else 5, 0, 0x400000, 0x400000, 120, 120, 4096)
    return header + segment


def pe(*, writable=False):
    raw = bytearray(1024)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 60, 128)
    raw[128:132] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', raw, 132, 0x8664, 1, 0, 0, 0, 240, 0x22)
    offset = 152
    struct.pack_into('<H', raw, offset, 0x20b)
    struct.pack_into('<I', raw, offset + 16, 4096)
    struct.pack_into('<Q', raw, offset + 24, 0x140000000)
    struct.pack_into('<II', raw, offset + 32, 4096, 512)
    struct.pack_into('<II', raw, offset + 56, 8192, 512)
    struct.pack_into('<H', raw, offset + 68, 3)
    struct.pack_into('<I', raw, offset + 108, 16)
    section = offset + 240
    raw[section:section + 8] = b'.text\0\0\0'
    struct.pack_into('<IIIIIIHHI', raw, section + 8, 1, 4096, 512, 512, 0, 0, 0, 0,
                     0xe0000020 if writable else 0x60000020)
    return bytes(raw)


def macho(*, arm=False, writable=False):
    cpu = 0x100000c if arm else 0x1000007
    header = struct.pack('<IIIIIIII', 0xfeedfacf, cpu, 0 if arm else 3, 2, 1, 72, 0, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, 72, b'__TEXT', 0x100000000, 4096,
                          0, 104, 7, 7 if writable else 5, 0, 0)
    return header + segment


def universal():
    first, second = macho(), macho(arm=True)
    raw = bytearray(8192 + len(second))
    struct.pack_into('>II', raw, 0, 0xcafebabe, 2)
    struct.pack_into('>IIIII', raw, 8, 0x1000007, 3, 4096, len(first), 12)
    struct.pack_into('>IIIII', raw, 28, 0x100000c, 0, 8192, len(second), 12)
    raw[4096:4096 + len(first)] = first
    raw[8192:] = second
    return bytes(raw)
