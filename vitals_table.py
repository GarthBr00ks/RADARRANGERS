import serial, struct, time
from rich.live import Live
from rich.table import Table

# CONFIGURE THESE
CLI_PORT = "COM5"      # Change to your CLI UART
DATA_PORT = "COM6"     # Change to your DATA UART
CFG_FILE = "Vital_Signs_With_Tracking_BOOST.cfg"
CLI_BAUD = 115200
DATA_BAUD = 1250000

# --- Send configuration over CLI UART ---
def send_cfg():
    with serial.Serial(CLI_PORT, CLI_BAUD, timeout=0.5) as cli, open(CFG_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('%'):
                cli.write((line + '\n').encode())
                time.sleep(0.05)
    print("✅ Config sent.\n")

# --- Parse vital signs TLV (very generic) ---
def parse_vitals(payload):
    try:
        # Typical payload has floats: breath, heart, confidence, range
        vals = struct.unpack('<8f', payload[:32])
        breath = vals[0]
        heart = vals[1]
        return round(breath, 2), round(heart, 2)
    except:
        return None, None

# --- Read UART frames ---
def read_vitals():
    ser = serial.Serial(DATA_PORT, DATA_BAUD, timeout=0.1)
    buffer = bytearray()
    MAGIC = b'\x02\x01\x04\x03\x06\x05\x08\x07'

    while True:
        buffer.extend(ser.read(4096))
        idx = buffer.find(MAGIC)
        if idx == -1:
            continue
        if len(buffer) < idx + 48:
            continue
        try:
            header = struct.unpack_from('<IIIIIIII', buffer, idx + 8)
            totalLen = header[1]
            numTLVs = header[6]
            if len(buffer) < idx + totalLen:
                continue
            offset = idx + 40
            for _ in range(numTLVs):
                tlv_type, tlv_len = struct.unpack_from('<II', buffer, offset)
                offset += 8
                if tlv_type in (0x18, 0x19, 0x20):  # candidates for vital signs TLV
                    payload = buffer[offset:offset + tlv_len - 8]
                    yield parse_vitals(payload)
                offset += tlv_len - 8
            buffer = buffer[idx + totalLen:]
        except struct.error:
            buffer.clear()

# --- Display live table ---
def main():
    send_cfg()

    table = Table(title="IWRL6432 Live Vital Signs")
    table.add_column("Time (s)")
    table.add_column("Breathing Rate (bpm)", justify="center")
    table.add_column("Heart Rate (bpm)", justify="center")

    start = time.time()
    with Live(table, refresh_per_second=4):
        for vitals in read_vitals():
            if vitals:
                br, hr = vitals
                elapsed = round(time.time() - start, 1)
                table.add_row(str(elapsed), str(br), str(hr))
                if len(table.rows) > 10:
                    table.rows.pop(0)

if __name__ == "__main__":
    main()
