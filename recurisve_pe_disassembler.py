import sys
import os
import pefile
from capstone import *

def find_section(pe, rva):
    """
    Given an RVA, find which section of the PE file contains it.
    Returns the section object, or None if not found.
    """
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + section.Misc_VirtualSize
        if start <= rva < end:
            return section
    return None

def rva_to_file_offset(pe, rva):
    """
    Convert an RVA (relative virtual address) to a file offset.
    """
    section = find_section(pe, rva)
    if not section:
        return None

    section_rva = section.VirtualAddress
    section_offset = section.PointerToRawData
    offset_in_section = rva - section_rva
    return section_offset + offset_in_section

def get_disassembler(pe):
    """
    Build a Capstone disassembler for the target architecture (32-bit or 64-bit).
    Enabling detail mode so insn.operands is available.
    """
    magic = pe.OPTIONAL_HEADER.Magic
    if magic == 0x10B:
        # 32-bit x86
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        print("[*] Detected x86 (32-bit) PE file.")
    elif magic == 0x20B:
        # 64-bit x86
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        print("[*] Detected x86-64 (64-bit) PE file.")
    else:
        raise RuntimeError(f"Unsupported PE magic (0x{magic:X}). Only x86/x64 are supported.")

    # IMPORTANT: Enable detail mode so insn.operands won't fail
    md.detail = True
    return md

def recursive_descent_disassemble(pe, md, pe_path):
    """
    Perform a naive 'recursive descent' style disassembly, reading directly
    from the file to handle cases where SizeOfRawData is incorrect.
    """
    file_size = os.path.getsize(pe_path)
    base_addr = pe.OPTIONAL_HEADER.ImageBase
    entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_file_offset = rva_to_file_offset(pe, entry_rva)

    print(f"DEBUG: Entry RVA=0x{entry_rva:X}, file offset=0x{entry_file_offset:X}")

    instructions_map = {}
    to_visit = [(entry_rva, entry_file_offset)]
    visited = set()

    while to_visit:
        current_rva, current_file_off = to_visit.pop()
        print(f"\nDEBUG: Visiting RVA=0x{current_rva:X} (file offset=0x{current_file_off:X})")

        if current_rva in visited:
            print("  Already visited, skipping.")
            continue
        visited.add(current_rva)

        section = find_section(pe, current_rva)
        if not section:
            print(f"  No section found for RVA=0x{current_rva:X}, skipping.")
            continue

        section_rva_start = section.VirtualAddress
        section_rva_end   = section_rva_start + section.Misc_VirtualSize
        offset_in_section = current_rva - section_rva_start

        # Calculate the absolute file offset
        absolute_start_offset = section.PointerToRawData + offset_in_section
        if absolute_start_offset < 0 or absolute_start_offset >= file_size:
            print(f"  Out of file bounds: 0x{absolute_start_offset:X} (file_size=0x{file_size:X}). Skipping.")
            continue

        # We'll read until the end of the file, or the end of the section in memory
        max_read_file = file_size - absolute_start_offset
        in_mem_left   = section_rva_end - current_rva
        read_len      = min(max_read_file, in_mem_left)

        if read_len <= 0:
            print("  read_len <= 0, skipping.")
            continue

        with open(pe_path, "rb") as f:
            f.seek(absolute_start_offset)
            code = f.read(read_len)

        print(f"  Successfully read {len(code)} bytes from offset=0x{absolute_start_offset:X} "
              f"(RVA=0x{current_rva:X}) in section '{section.Name}'.")

        decoded_any = False
        for insn in md.disasm(code, base_addr + current_rva):
            decoded_any = True
            insn_rva = insn.address - base_addr
            hex_bytes = " ".join(f"{b:02X}" for b in insn.bytes)
            asm_text = f"{insn.mnemonic} {insn.op_str}"
            instructions_map[insn_rva] = (hex_bytes, asm_text)

            mnem_low = insn.mnemonic.lower()
            # If call/jmp is direct, follow
            if mnem_low.startswith("call") or mnem_low.startswith("jmp"):
                # Now that md.detail=True, insn.operands works!
                if len(insn.operands) == 1 and insn.operands[0].type == 1:  # 1 = CS_OP_IMM
                    target_va = insn.operands[0].imm
                    target_rva = target_va - base_addr
                    target_file_off = rva_to_file_offset(pe, target_rva)
                    if target_file_off is not None:
                        print(f"  Following branch to RVA=0x{target_rva:X}")
                        to_visit.append((target_rva, target_file_off))

            if mnem_low.startswith("ret"):
                break

        if not decoded_any:
            print("  Capstone returned zero instructions from this block.")

    return instructions_map

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_pe_file>")
        sys.exit(1)

    pe_path = sys.argv[1]
    pe = pefile.PE(pe_path)
    md = get_disassembler(pe)

    instructions = recursive_descent_disassemble(pe, md, pe_path)

    print("\n--- Disassembly (Recursive Descent) ---")
    if not instructions:
        print("[!] No instructions found or could not disassemble any code.")
        return

    for rva in sorted(instructions):
        hex_bytes, asm_text = instructions[rva]
        print(f"0x{rva:08X}:  {hex_bytes:<20}  {asm_text}")

if __name__ == "__main__":
    main()
