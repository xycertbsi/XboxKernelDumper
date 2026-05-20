import socket
import os
import struct

XBOX_IP = "192.168.100.50"
XBOX_PORT = 730
KERNEL_BASE = 0x80040000
KERNEL_SIZE = 0x1B0000
KERNEL_FILE = "kernel_final.bin"

def check_kernel_exists():
    if os.path.exists(KERNEL_FILE):
        size = os.path.getsize(KERNEL_FILE)
        print(f"[OK] Found {KERNEL_FILE} ({size:#x} bytes), skipping dump.")
        return True
    return False

def xbdm_dump(ip, port, addr, size, filename):
    print(f"Connecting to {ip}:{port}...")
    s = socket.create_connection((ip, port), timeout=10)
    banner = s.recv(256).decode()
    print(f"XBDM: {banner.strip()}")

    data = bytearray()
    chunk_size = 0x40

    print(f"Dumping {size:#x} bytes from {addr:#010x}...")
    for offset in range(0, size, chunk_size):
        current = addr + offset
        length = min(chunk_size, size - offset)

        cmd = f'getmem addr={current:#010x} length={length:#x}\r\n'
        s.sendall(cmd.encode())

        resp = b''
        while b'\r\n.\r\n' not in resp:
            resp += s.recv(4096)

        lines = resp.split(b'\r\n')
        hex_line = lines[1].decode('ascii').strip()
        data.extend(bytes.fromhex(hex_line))

        if offset % 0x10000 == 0:
            print(f"  {offset/size*100:.1f}% ({offset:#x}/{size:#x})")

    s.close()
    with open(filename, 'wb') as f:
        f.write(data)
    print(f"[OK] Saved {len(data):#x} bytes to {filename}")
    return bytes(data)

def parse_pe_sections(data):
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+2] != b'PE':
        print("❌ No PE signature found!")
        return {}

    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    opt_hdr_size = struct.unpack_from('<H', data, pe_offset + 0x14)[0]
    section_offset = pe_offset + 0x18 + opt_hdr_size

    sections = {}
    print(f"\n=== PE Sections ({num_sections}) ===")
    for i in range(num_sections):
        s = section_offset + (i * 0x28)
        name = data[s:s+8].decode('ascii', errors='replace').strip('\x00')
        vaddr = struct.unpack_from('<I', data, s + 0x0C)[0]
        vsize = struct.unpack_from('<I', data, s + 0x10)[0]
        print(f"  {name:<12} vaddr={vaddr:#010x} vsize={vsize:#010x}")
        sections[name] = (vaddr, vsize)
    return sections

def ppc_score(data, sample=4096):
    ppc_bytes = [0x3C,0x38,0x4B,0x48,0x39,0x3D,0x80,0x81,0x7C,0x60,0x4C,0x2C]
    return sum(1 for i in range(0, min(sample, len(data)), 4)
               if data[i] in ppc_bytes)

def extract_section(data, sections, name):
    if name not in sections:
        print(f"❌ Section {name} not found!")
        return None
    vaddr, vsize = sections[name]
    chunk = data[vaddr:vaddr + vsize]
    print(f"[OK] Extracted {name}: {len(chunk):#x} bytes, PPC score: {ppc_score(chunk)}/1024")
    return chunk

if not check_kernel_exists():
    ip = input("Xbox IP [192.168.100.50] > ").strip() or XBOX_IP
    port_in = input("XBDM port [730] > ").strip()
    port = int(port_in) if port_in else XBOX_PORT
    xbdm_dump(ip, port, KERNEL_BASE, KERNEL_SIZE, KERNEL_FILE)

with open(KERNEL_FILE, "rb") as f:
    krl = f.read()

print(f"\nKernel size: {len(krl):#x}")
print(f"Header: {krl[:4].hex().upper()}")

sections = parse_pe_sections(krl)

text = extract_section(krl, sections, ".text")
if text:
    with open("kernel_text.bin", "wb") as f:
        f.write(text)

rdata = extract_section(krl, sections, ".rdata")
if rdata:
    with open("kernel_rdata.bin", "wb") as f:
        f.write(rdata)

print("\n=== Kernel strings (first 30) ===")
import re
if rdata:
    strings = re.findall(b'[\x20-\x7E]{8,}', rdata)
    for s in strings[:30]:
        print(f"  {s.decode()}")

print("\n[OK] Done!")