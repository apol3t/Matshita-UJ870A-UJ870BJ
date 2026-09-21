import ctypes
from ctypes import wintypes
import time
import datetime
import sys
import os

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014

kernel32 = ctypes.windll.kernel32

CHUNK_COUNT = 2048       # 2 MB / 1024 byte = 2048 blok
HEADER_SIZE = 0x30
DATA_SIZE = 0x400        # 1024 byte
TOTAL_SIZE = HEADER_SIZE + DATA_SIZE  # 0x430 (1072 byte)

class SPTD(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT), ("ScsiStatus", wintypes.BYTE),
        ("PathId", wintypes.BYTE), ("TargetId", wintypes.BYTE), ("Lun", wintypes.BYTE),
        ("CdbLength", wintypes.BYTE), ("SenseInfoLength", wintypes.BYTE), ("DataIn", wintypes.BYTE),
        ("DataTransferLength", wintypes.ULONG), ("TimeOutValue", wintypes.ULONG),
        ("DataBuffer", ctypes.c_void_p), ("SenseInfoOffset", wintypes.ULONG),
        ("Cdb", wintypes.BYTE * 16),
    ]

class SPTD_SENSE(ctypes.Structure):
    _fields_ = [("sptd", SPTD), ("SenseBuf", wintypes.BYTE * 24)]

def send_scsi(handle, cdb, data_in, size, data_buffer=None):
    sptd = SPTD_SENSE()
    if data_buffer is None and size > 0:
        data_buffer = (ctypes.c_ubyte * size)()
    
    sptd.sptd.Length = ctypes.sizeof(SPTD)
    sptd.sptd.CdbLength = 12
    sptd.sptd.SenseInfoLength = 24
    sptd.sptd.DataIn = data_in
    sptd.sptd.DataTransferLength = size if data_in != 2 else 0
    sptd.sptd.TimeOutValue = 1800
    sptd.sptd.DataBuffer = ctypes.cast(data_buffer, ctypes.c_void_p) if data_buffer else None
    sptd.sptd.SenseInfoOffset = ctypes.sizeof(SPTD)
    
    for i, b in enumerate(cdb[:12]):
        sptd.sptd.Cdb[i] = b
    
    bytes_returned = wintypes.DWORD(0)
    result = kernel32.DeviceIoControl(
        handle, IOCTL_SCSI_PASS_THROUGH_DIRECT,
        ctypes.byref(sptd), ctypes.sizeof(sptd),
        ctypes.byref(sptd), ctypes.sizeof(sptd),
        ctypes.byref(bytes_returned), None
    )
    
    status = sptd.sptd.ScsiStatus
    success = (result and status == 0x00)
    return success, sptd, bytes(data_buffer) if data_buffer else b""

def unlock_device(handle):
    now = datetime.datetime.now()
    sec, minute = now.second, now.minute
    
    a1 = (~sec) & 0xFF
    a2 = (~minute) & 0xFF
    a3 = (89 - sec) & 0xFF
    a4 = (-minute - 92) & 0xFF
    a5 = (118 - sec) & 0xFF
    a6 = (101 - minute) & 0xFF
    
    if a3 == 255 and a4 == 255:
        a3, a4 = 0, 0
    
    cdb = [0xED, 0x00, a1, a2, a3, a4, 0x10, a5, a6, 0x10, 0x00, 0x3C]
    success, _, _ = send_scsi(handle, cdb, data_in=1, size=0x1000)
    return success

def prime_bridge(handle):
    cdb_ea = [
        0xEA, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x00, 0x04, 0x30,
        0x00, 0x00, 0x00
    ]
    buf = (ctypes.c_ubyte * TOTAL_SIZE)(*([0x00] * TOTAL_SIZE))
    success, _, _ = send_scsi(handle, cdb_ea, data_in=0, size=TOTAL_SIZE, data_buffer=buf)
    return success

def read_e8(handle, address, total_size):
    cdb = [
        0xE8, 0x00, 0x00,
        (address >> 16) & 0xFF,
        (address >> 8) & 0xFF,
        address & 0xFF,
        (total_size >> 16) & 0xFF,
        (total_size >> 8) & 0xFF,
        total_size & 0xFF,
        0x00, 0x00, 0x00
    ]
    return send_scsi(handle, cdb, data_in=1, size=total_size)

def main():
    device_path = r"\\.\CDROM0"
    
    print("=" * 70)
    print("💾 UJ870BJ TAM 2 MB FIRMWARE DUMPER (2048 CHUNKS)")
    print("=" * 70)
    
    handle = kernel32.CreateFileW(
        device_path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None
    )
    
    if handle in (-1, 0xFFFFFFFFFFFFFFFF):
        print("❌ Cihaz açılamadı! Yönetici olarak çalıştırın.")
        return
    
    print("[1] Kilit açılıyor...")
    if not unlock_device(handle):
        print("❌ Kilit açılamadı!")
        kernel32.CloseHandle(handle)
        return
    print("✅ Cihaz kilidi açıldı.")
    
    print("[2] 0x2D dizisi gönderiliyor...")
    cdb_2d = [
        [0x2D, 0x00, 0x81, 0x7D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x2D, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x2D, 0x00, 0x82, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ]
    for cdb in cdb_2d:
        send_scsi(handle, cdb, data_in=2, size=0)
        time.sleep(0.02)
    
    print("[3] Prime işlemi yapılıyor...")
    if not prime_bridge(handle):
        print("❌ İlk Prime başarısız!")
        kernel32.CloseHandle(handle)
        return
    print("✅ Memory Bridge devrede.")
    
    print(f"\n[4] 2 MB bellek alanı okunuyor (0x000000 - 0x1FFFFF)...")
    
    firmware_data = bytearray()
    header_data = bytearray()
    errors = 0
    
    for chunk in range(CHUNK_COUNT):
        addr = chunk * DATA_SIZE  # Adres doğrudan 1024 adımlarla artar
        
        pct = (chunk + 1) * 100 // CHUNK_COUNT
        sys.stdout.write(f"\r  [{pct:3d}%] Chunk {chunk + 1}/{CHUNK_COUNT} @ 0x{addr:06X}")
        sys.stdout.flush()
        
        success, sptd, data = read_e8(handle, addr, TOTAL_SIZE)
        
        if not success:
            # Köprü düşmüş olabilir, prime edip tekrar dene
            prime_bridge(handle)
            time.sleep(0.01)
            success, sptd, data = read_e8(handle, addr, TOTAL_SIZE)
        
        if success and len(data) >= TOTAL_SIZE:
            header_data.extend(data[:HEADER_SIZE])
            firmware_data.extend(data[HEADER_SIZE:HEADER_SIZE + DATA_SIZE])
        else:
            firmware_data.extend(b'\x00' * DATA_SIZE)
            errors += 1
        
        time.sleep(0.005)
    
    print(f"\n\n[✓] Döküm tamamlandı!")
    print(f"    Toplam Veri: {len(firmware_data)} byte ({len(firmware_data) / 1024 / 1024:.2f} MB)")
    print(f"    Hatalı chunk sayısı: {errors}")
    
    timestamp = int(time.time())
    fw_file = f"uj870_full_2mb_{timestamp}.bin"
    hdr_file = f"uj870_headers_2mb_{timestamp}.bin"
    
    with open(fw_file, "wb") as f:
        f.write(firmware_data)
    with open(hdr_file, "wb") as f:
        f.write(header_data)
    
    print(f"\n💾 2 MB Ham Firmware kaydedildi: {fw_file}")
    print(f"💾 Başlık verileri kaydedildi:    {hdr_file}")
    
    kernel32.CloseHandle(handle)

if __name__ == "__main__":
    main()