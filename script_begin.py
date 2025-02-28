import pefile

pe = pefile.PE("hello.exe")

entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
entry_offset = None

for section in pe.sections:
    start = section.VirtualAddress
    end   = start + section.Misc_VirtualSize
    if start <= entry_rva < end:
        offset_within_section = entry_rva - start
        # Use min of raw size vs. virtual size
        size_to_read = min(section.SizeOfRawData, section.Misc_VirtualSize) - offset_within_section
        file_offset = section.PointerToRawData + offset_within_section
        entry_offset = file_offset
        break

print(f"Entry RVA: 0x{entry_rva:08X}")
print(f"Entry offset in file: {entry_offset}")

if entry_offset:
    with open("hello.exe", "rb") as f:
        f.seek(entry_offset)
        first_16 = f.read(16)
        print(f"First 16 bytes at entry: {[f'0x{b:02X}' for b in first_16]}")
