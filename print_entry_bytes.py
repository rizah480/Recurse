import pefile

pe = pefile.PE("hello.exe")

entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f"Entry RVA: 0x{entry_rva:08X}")

# Find which section this RVA belongs to
section_for_entry = None
for section in pe.sections:
    start = section.VirtualAddress
    end = start + section.Misc_VirtualSize
    if start <= entry_rva < end:
        section_for_entry = section
        break

if section_for_entry is None:
    print("Could not find a section containing the entry point.")
    exit(1)

offset_within_section = entry_rva - section_for_entry.VirtualAddress
file_offset = section_for_entry.PointerToRawData + offset_within_section

print(f"Section name: {section_for_entry.Name}")
print(f"Section RVA range: 0x{section_for_entry.VirtualAddress:08X} - 0x{section_for_entry.VirtualAddress + section_for_entry.Misc_VirtualSize:08X}")
print(f"Section raw data offset: 0x{section_for_entry.PointerToRawData:08X}")
print(f"Calculated file offset for entry: 0x{file_offset:08X}")

with open("hello.exe", "rb") as f:
    f.seek(file_offset)
    first_32_bytes = f.read(32)  # read first 32 bytes at entry
    print("\nFirst 32 bytes at entry point:")
    for i, b in enumerate(first_32_bytes):
        print(f"  {i:02d}: 0x{b:02X}")
