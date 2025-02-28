import pefile

if __name__ == "__main__":
    try:
        pe = pefile.PE("hello.exe")  # Fix: Should check "hello.exe", not "hello.c"
        print("✅ Valid Windows PE file detected.")
    except pefile.PEFormatError:
        print("❌ Not a valid PE file.")

    # Read magic bytes from hello.exe
    with open("hello.exe", "rb") as f:
        magic = f.read(2)

    print(f"Magic bytes: {magic.hex().upper()}")

    if magic == b'MZ':
        print("✅ This is a valid Windows PE file.")
    else:
        print("❌ This is NOT a valid PE file (wrong format).")





