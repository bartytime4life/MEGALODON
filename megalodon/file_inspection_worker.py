"""Fixed worker entry point. Only invoked inside the file-inspection sandbox."""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, '/worker')
from file_inspection_contract import MAX_SLICES, validate_structure  # noqa: E402

INPUT = '/input/program'


def classify():
    """Admit executable formats, not archives, core dumps or object files."""
    size = os.stat(INPUT).st_size
    with open(INPUT, 'rb') as stream:
        head = stream.read(64)
        if head[:4] == b'\x7fELF':
            if len(head) < 52 or head[4] not in (1, 2) or head[5] not in (1, 2):
                raise ValueError('Invalid ELF header.')
            endian = '<' if head[5] == 1 else '>'
            if struct.unpack_from(endian + 'H', head, 16)[0] not in (2, 3):
                return None
            return 'ELF', 1
        if head[:2] == b'MZ':
            if len(head) != 64:
                raise ValueError('Invalid PE header.')
            offset = struct.unpack_from('<I', head, 60)[0]
            if not 64 <= offset <= size - 24:
                raise ValueError('Invalid PE offset.')
            stream.seek(offset)
            if stream.read(4) != b'PE\x00\x00':
                raise ValueError('Invalid PE signature.')
            return 'PE', 1
        magic = head[:4]
        if magic in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'):
            endian = '<' if magic[0] in (0xce, 0xcf) else '>'
            if len(head) < 28 or struct.unpack_from(endian + 'I', head, 12)[0] not in (2, 6, 8):
                return None
            return 'Mach-O', 1
        if magic in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
            endian = '>' if magic[0] == 0xca else '<'
            number = struct.unpack_from(endian + 'I', head, 4)[0]
            if not 1 <= number <= MAX_SLICES:
                raise ValueError('Universal slice limit.')
            wide = magic in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
            width = 32 if wide else 20
            stream.seek(8)
            records = stream.read(width * number)
            if len(records) != width * number:
                raise ValueError('Truncated universal table.')
            regions = []
            for i in range(number):
                offset, length = struct.unpack_from(endian + ('QQ' if wide else 'II'), records, i * width + 8)
                if offset < 8 + width * number or length < 28 or offset + length > size:
                    raise ValueError('Invalid universal slice.')
                if any(offset < end and offset + length > start for start, end in regions):
                    raise ValueError('Overlapping universal slices.')
                regions.append((offset, offset + length))
                stream.seek(offset)
                header = stream.read(16)
                if header[:4] not in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'):
                    raise ValueError('Unsupported universal slice.')
                inner_endian = '<' if header[0] in (0xce, 0xcf) else '>'
                if struct.unpack_from(inner_endian + 'I', header, 12)[0] not in (2, 6, 8):
                    raise ValueError('Non-executable universal slice.')
            return 'Mach-O', number
    return None


def inspect_lief():
    admitted = classify()
    if admitted is None:
        return {'state': 'unsupported'}
    sys.path.insert(0, '/runtime/python')
    import lief
    lief.logging.disable()
    kind, detected = admitted
    if kind == 'ELF':
        config = lief.ELF.ParserConfig()
        for name in ('parse_relocations', 'parse_notes', 'parse_overlay', 'parse_symtab_symbols'):
            if hasattr(config, name):
                setattr(config, name, False)
        binary = lief.ELF.parse(INPUT, config)
        if binary is None:
            raise ValueError('ELF parse failed.')
        rows = [dict(architecture=binary.header.machine_type.name, bits=64 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32,
                     sections=len(binary.sections), imports=len(binary.imported_functions),
                     writable_executable=sum(1 for s in binary.segments if int(s.flags) & 3 == 3))]
    elif kind == 'PE':
        config = lief.PE.ParserConfig()
        for name in ('parse_signature', 'parse_exports', 'parse_resources', 'parse_reloc', 'parse_debug', 'parse_exceptions'):
            if hasattr(config, name):
                setattr(config, name, False)
        binary = lief.PE.parse(INPUT, config)
        if binary is None:
            raise ValueError('PE parse failed.')
        rows = [dict(architecture=binary.header.machine.name, bits=64 if binary.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS else 32,
                     sections=len(binary.sections), imports=len(binary.imported_functions),
                     writable_executable=sum(1 for s in binary.sections if int(s.characteristics) & 0xa0000000 == 0xa0000000))]
    else:
        binaries = lief.MachO.parse(INPUT)
        if binaries is None or len(binaries) != detected:
            raise ValueError('Incomplete universal parse.')
        rows = [dict(architecture=b.header.cpu_type.name, bits=64 if b.header.is_64bit else 32,
                     sections=len(b.sections), imports=len(b.imported_functions),
                     writable_executable=sum(1 for s in b.segments if int(s.init_protection) & 6 == 6)) for b in binaries]
    structure = dict(format=kind, slices_detected=detected, slices=rows)
    return {'state': 'completed', 'structure': validate_structure(structure)}


def main():
    try:
        result = inspect_lief()
    except Exception:
        # Native diagnostics and filenames never cross the normalized boundary.
        result = {'state': 'failed'}
    print(json.dumps(result, allow_nan=False, separators=(',', ':')))


if __name__ == '__main__':
    main()
