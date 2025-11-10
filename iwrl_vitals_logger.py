# Create a self-contained Python script for reading TI IWRL6432 Vital Signs over UART.
# It sends a .cfg over the CLI port, then parses binary TLVs from the DATA port.
# The script is conservative and defensive: it will print TLV types it sees each frame
# and attempts to parse a "vital signs" TLV if present (you can adjust TLV_TYPE values as needed).
script = r'''#!/usr/bin/env python3
"""
iwr_vitals_logger.py
--------------------
Minimal, standalone Python script to run the TI IWRL6432 Vital Signs demo without the GUI.
- Sends a .cfg file over the CLI UART
- Reads binary TLV frames from the DATA UART
- Prints breathing/heart rate when a Vital Signs TLV is found
- Optionally logs to CSV

USAGE (Windows example):
    py iwr_vitals_logger.py --cli COM5 --data COM6 --cfg vitalsigns.cfg --csv vitals_log.csv

USAGE (Linux/RPi example):
    python3 iwr_vitals_logger.py --cli /dev/ttyACM0 --data /dev/ttyACM1 --cfg vitalsigns.cfg

Notes:
- CLI baud is typically 115200, DATA is typically 921600 for TI demos.
- If you are unsure of the Vital Signs TLV ID for your firmware, run once without --csv;
  the script will print "TLVs seen this frame: [...]" so you can identify it.
- Then update TLV_TYPE_VITAL_SIGNS below accordingly.
"""

import argparse
import time
import struct
import sys
import csv
from collections import deque

try:
    import serial
except ImportError:
    print("Please: pip install pyserial")
    sys.exit(1)

MAGIC = b'\x02\x01\x04\x03\x06\x05\x08\x07'  # TI mmWave UART packet magic (little-endian sequence)
HEADER_LEN = 40  # bytes after magic in many SDKs; we'll validate via 'totalPacketLen'

# ---- Likely TLV Type IDs (update if your firmware uses different IDs) ----
# For many TI UART outputs, point cloud / stats / tracking use these ranges. Vital Signs lab may use a custom ID.
# We'll try common candidates and also print seen TLVs so you can adjust quickly.
TLV_TYPE_VITAL_SIGNS_CANDIDATES = {0x18, 0x19, 0x1A, 0x20}  # try a handful; adjust after first run
# --------------------------------------------------------------------------

def send_cfg(cli_port: str, cfg_path: str, baud: int = 115200, delay: float = 0.05):
    """Send a .cfg file over the CLI UART port line by line."""
    print(f"[CFG] Sending {cfg_path} to {cli_port} @ {baud}...")
    with serial.Serial(cli_port, baud, timeout=1) as ser, open(cfg_path, 'r') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('%'):
                continue
            ser.write((line + '\n').encode('utf-8'))
            time.sleep(delay)
            # Read any CLI echo/response non-blocking
            resp = ser.read(ser.in_waiting or 1)
            if resp:
                try:
                    sys.stdout.write(resp.decode('utf-8', errors='ignore'))
                except Exception:
                    pass
    print("[CFG] Done.\n")


def find_magic(buffer: bytearray):
    """Find magic word index in buffer, return start or -1."""
    try:
        return buffer.index(MAGIC)
    except ValueError:
        return -1


def read_frame(data_ser: serial.Serial, scratch: bytearray) -> bytes:
    """
    Read one UART frame (magic + payload). Returns the full packet bytes or b'' on timeout.
    Strategy: accumulate bytes, sync on MAGIC, then read 'totalPacketLen' from header.
    """
    t0 = time.time()
    while time.time() - t0 < 1.0:  # 1s timeout to find a full packet
        chunk = data_ser.read(4096)
        if chunk:
            scratch.extend(chunk)

            # Try to sync
            while True:
                idx = find_magic(scratch)
                if idx < 0:
                    # keep last 7 bytes in case of partial magic at boundary
                    if len(scratch) > 7:
                        del scratch[:-7]
                    break

                if len(scratch) < idx + 8 + HEADER_LEN:
                    # need more data
                    break

                # Unpack a conservative header: version (I), totalLen (I), platform (I), frameNum (I),
                # timeCpuCycles (I), numDetectedObj (I), numTLVs (I), subFrameNum (I)
                header_start = idx + 8
                try:
                    header = struct.unpack_from('<IIIIIIII', scratch, header_start)
                except struct.error:
                    # Not enough data; wait for more
                    break

                total_len = header[1]
                num_tlvs = header[6]
                if total_len < 48 or total_len > 200000:
                    # Unreasonable; drop magic and resync
                    del scratch[:idx+8]
                    continue

                # If we don't yet have the whole packet, read more
                if len(scratch) < idx + total_len:
                    break

                packet = bytes(scratch[idx: idx + total_len])
                # Remove consumed bytes
                del scratch[: idx + total_len]
                return packet
        else:
            # small sleep to avoid busy loop
            time.sleep(0.002)
    return b''


def parse_tlvs(packet: bytes):
    """
    Given a full packet (starting with MAGIC), yield (tlv_type, payload_bytes).
    Header is assumed <8B magic> + <8*4B fields> = 40B header (typical); tlvs follow.
    """
    # Unpack header again to get TLV count and header size
    try:
        version, totalLen, platform, frameNum, timeCpu, numDet, numTLV, subFrame = struct.unpack_from('<IIIIIIII', packet, 8)
    except struct.error:
        return []

    tlvs = []
    offset = 8 + 32  # magic + 8*4B
    # Some SDKs add "frameHeaderTLV" afterwards; we handle generically: next bytes are TLVs anyway per 'totalLen'
    for _ in range(numTLV):
        if offset + 8 > len(packet):
            break
        tlv_type, tlv_len = struct.unpack_from('<II', packet, offset)
        offset += 8
        if offset + tlv_len - 8 > len(packet):
            break
        payload = packet[offset: offset + tlv_len - 8]
        tlvs.append((tlv_type, payload))
        offset += (tlv_len - 8)
    return tlvs


def parse_vitals_payload(payload: bytes):
    """
    Attempt to parse a plausible vital-signs record.
    Many labs pack floats in order: breathRate, heartRate, confidence, rangeBin or similar.
    We'll try a generic layout of 6-12 floats; adjust if your firmware differs.
    Returns a dict if successful, else None.
    """
    # Try the most common case: 8 floats (32 bytes)
    out = {}
    try:
        floats = struct.unpack('<8f', payload[:32])
        # Heuristics: breathing typically 6-40 bpm, heart 40-180 bpm. Filter by that.
        # We don't know the exact order, but many TI labs put breath first, heart later.
        # We'll try to infer likely idx by bounds.
        candidates = [(i, v) for i, v in enumerate(floats)]
        br = next((v for i, v in candidates if 4 <= v <= 60), None)
        hr = next((v for i, v in candidates if 30 <= v <= 200), None)
        out['breath_bpm'] = br
        out['heart_bpm'] = hr
        out['raw'] = floats
        return out
    except struct.error:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(description="IWRL6432 Vital Signs UART reader")
    ap.add_argument('--cli', required=True, help='CLI COM port (e.g., COM5 or /dev/ttyACM0)')
    ap.add_argument('--data', required=True, help='DATA COM port (e.g., COM6 or /dev/ttyACM1)')
    ap.add_argument('--cfg', required=True, help='Path to .cfg to send')
    ap.add_argument('--csv', default='', help='Optional CSV log path')
    ap.add_argument('--cli_baud', type=int, default=115200)
    ap.add_argument('--data_baud', type=int, default=921600)
    ap.add_argument('--warmup_sec', type=float, default=5.0, help='Ignore vitals for first N seconds')
    args = ap.parse_args()

    # Send configuration
    send_cfg(args.cli, args.cfg, baud=args.cli_baud)

    # Open DATA UART
    ser = serial.Serial(args.data, args.data_baud, timeout=0.05)
    scratch = bytearray()

    csv_writer = None
    if args.csv:
        csvf = open(args.csv, 'w', newline='')
        csv_writer = csv.writer(csvf)
        csv_writer.writerow(['t_sec', 'breath_bpm', 'heart_bpm', 'tlv_types'])

    t_start = time.time()
    recent_vitals = deque(maxlen=10)
    print("[DATA] Listening for frames... Ctrl+C to stop.\n")

    try:
        while True:
            pkt = read_frame(ser, scratch)
            if not pkt:
                continue

            tlvs = parse_tlvs(pkt)
            tlv_types = [t for t, _ in tlvs]

            # First pass: try candidates for vital signs TLV
            vit = None
            for t, payload in tlvs:
                if t in TLV_TYPE_VITAL_SIGNS_CANDIDATES:
                    vit = parse_vitals_payload(payload)
                    if vit:
                        break

            now = time.time() - t_start
            if vit and now >= args.warmup_sec:
                br = vit.get('breath_bpm')
                hr = vit.get('heart_bpm')
                if br is not None or hr is not None:
                    recent_vitals.append((now, br, hr))
                    print(f"[{now:7.2f}s] Breath: {br if br is not None else '---':>5} bpm | Heart: {hr if hr is not None else '---':>5} bpm | TLVs seen: {tlv_types}")
                    if csv_writer:
                        csv_writer.writerow([f"{now:.3f}", f"{br:.3f}" if br is not None else "", f"{hr:.3f}" if hr is not None else "", tlv_types])
                        csvf.flush()
                else:
                    print(f"[{now:7.2f}s] TLVs seen: {tlv_types} (vitals TLV candidate present but fields ambiguous)")
            else:
                # Show TLVs so the user can identify the correct type ID
                print(f"[{now:7.2f}s] TLVs seen: {tlv_types} (warming up or no vitals parsed)")

    except KeyboardInterrupt:
        print("\n[EXIT] Stopping.")
    finally:
        try:
            ser.close()
        except Exception:
            pass
        if csv_writer:
            csvf.close()


if __name__ == '__main__':
    main()
'''
open('/mnt/data/iwr_vitals_logger.py', 'w', encoding='utf-8').write(script)
print("Saved to /mnt/data/iwr_vitals_logger.py")

