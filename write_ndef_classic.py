#!/usr/bin/env python
"""
A command-line tool to write an NDEF URL record to a MIFARE Classic 1K card using
an ACS ACR1251 reader on Windows, with authentication using a candidate key list.
It now supports writing NDEF messages spanning multiple sectors (from sector 1 up to 15).
If the message exceeds 15 sectors (i.e. >720 bytes available), an error is issued.

By default, the tag is formatted so that:
  - Sector 0’s user area (blocks 1–2) is filled with a fixed pattern:
      first 2 bytes: "14 01", then the rest filled with alternating "03" and "E1".
  - All trailer blocks (last block of each sector) are updated to new keys:
      Sector 0’s A key becomes A0A1A2A3A4A5;
      All other sectors’ A key become D3F7D3F7D3F7;
      Access Bits are fixed as FF078069 and Key B is set to D3F7D3F7D3F7.
If the --no-format flag is given, only the NDEF message is written.
  
Requirements:
  - Python 3.x
  - pyscard (install via: pip install pyscard)
"""

import sys
import time
import argparse
import os
import logging
from smartcard.System import readers
from smartcard.util import toHexString

# Set up logging: default level INFO; DEBUG messages hidden unless configured.
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants for APDU commands and keys
DEFAULT_AUTH_KEY = [0xFF] * 6  # default key for unformatted card (if keys.txt is absent)
KEY_SLOT = 0x00   # use key slot 0 for volatile key storage

# New keys to be programmed into trailer blocks:
FALLBACK_SECTOR0_KEY = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5]   # For sector 0 A key
FALLBACK_DEFAULT_KEY = [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7]    # For all other sectors A key
# Key B is always set to the same as FALLBACK_DEFAULT_KEY.
KEYB_DEFAULT = FALLBACK_DEFAULT_KEY[:]
ACCESS_BITS = [0xFF, 0x07, 0x80, 0x69]  # Fixed access bits for trailer blocks

def construct_ndef(url):
    """
    Construct an NDEF TLV for a URL record.
    Returns a bytes object containing the TLV.
    """
    url_bytes = url.encode('utf-8')
    payload = bytes([0x00]) + url_bytes  # 0x00 indicates no prefix abbreviation
    header = bytes([0xD1])
    type_length = bytes([0x01])  # for 'U'
    payload_length = bytes([len(payload)])
    record_type = b'U'
    ndef_record = header + type_length + payload_length + record_type + payload
    tlv = bytes([0x03, len(ndef_record)]) + ndef_record + bytes([0xFE])
    return tlv

def load_key(connection, key, key_slot=KEY_SLOT):
    """
    Load a 6-byte key into the reader's volatile memory.
    APDU: FF 82 00 <key_slot> 06 <key bytes>
    """
    if len(key) != 6:
        logger.error("Key must be 6 bytes long.")
        sys.exit(1)
    apdu = [0xFF, 0x82, 0x00, key_slot, 0x06] + key
    logger.debug(f"Loading candidate key {toHexString(key)} into slot {key_slot}")
    response, sw1, sw2 = connection.transmit(apdu)
    if (sw1, sw2) != (0x90, 0x00):
        logger.debug(f"Error loading key {toHexString(key)}: SW1={sw1:02X}, SW2={sw2:02X}")
    else:
        logger.debug("Key loaded successfully.")

def try_authenticate_block(connection, block, candidate_keys):
    """
    Try to authenticate the given block using each candidate key.
    For each candidate key, try it as an A key (0x60) then as a B key (0x61).
    Returns (key, key_type) if successful.
    """
    for key in candidate_keys:
        load_key(connection, key, KEY_SLOT)
        apdu = [0xFF, 0x86, 0x00, 0x00, 0x05,
                0x01, 0x00, block, 0x60, KEY_SLOT]
        logger.debug(f"Trying candidate key {toHexString(key)} as A key for block {block}")
        response, sw1, sw2 = connection.transmit(apdu)
        if (sw1, sw2) == (0x90, 0x00):
            logger.debug(f"Block {block} authenticated with key {toHexString(key)} as A key")
            return key, 0x60
        load_key(connection, key, KEY_SLOT)
        apdu = [0xFF, 0x86, 0x00, 0x00, 0x05,
                0x01, 0x00, block, 0x61, KEY_SLOT]
        logger.debug(f"Trying candidate key {toHexString(key)} as B key for block {block}")
        response, sw1, sw2 = connection.transmit(apdu)
        if (sw1, sw2) == (0x90, 0x00):
            logger.debug(f"Block {block} authenticated with key {toHexString(key)} as B key")
            return key, 0x61
    logger.error(f"Authentication failed for block {block} with all candidate keys.")
    sys.exit(1)

def read_candidate_keys(filename="keys.txt"):
    """
    Read candidate keys from a text file.
    Each line should contain one key (12 hex digits, no extra text).
    Returns a list of keys (each key is a list of 6 integers).
    """
    candidate_keys = []
    if not os.path.exists(filename):
        logger.warning(f"Candidate key file '{filename}' not found. Using default key.")
        candidate_keys.append(DEFAULT_AUTH_KEY)
        return candidate_keys
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if len(line) != 12:
                logger.warning(f"Skipping invalid key line: {line}")
                continue
            try:
                key = [int(line[i:i+2], 16) for i in range(0, 12, 2)]
                candidate_keys.append(key)
            except Exception as e:
                logger.warning(f"Error parsing key '{line}': {e}")
    if not candidate_keys:
        candidate_keys.append(DEFAULT_AUTH_KEY)
    return candidate_keys

def write_block(connection, block, data):
    """
    Write 16 bytes of data to the specified block.
    APDU: FF D6 00 <block> 10 <16 bytes>
    """
    if len(data) < 16:
        data = data.ljust(16, b'\x00')
    elif len(data) > 16:
        data = data[:16]
    apdu = [0xFF, 0xD6, 0x00, block, 0x10] + list(data)
    logger.debug(f"Writing block {block}: {toHexString(list(data))}")
    response, sw1, sw2 = connection.transmit(apdu)
    if (sw1, sw2) == (0x90, 0x00):
        logger.debug(f"Block {block} written successfully.")
    else:
        logger.error(f"Error writing block {block}: SW1={sw1:02X}, SW2={sw2:02X}")
        sys.exit(1)

def write_ndef_message_multi(connection, ndef_message, candidate_keys):
    """
    Write the NDEF TLV (padded to 48-byte chunks) into consecutive sectors.
    Each sector (from 1 to 15) provides 48 bytes (3 blocks of 16 bytes each).
    If the NDEF message requires more than 15 sectors, an error is issued.
    """
    total_length = len(ndef_message)
    sectors_needed = (total_length + 47) // 48  # Ceiling division
    if sectors_needed > 15:
        logger.error(f"NDEF message too long: requires {sectors_needed} sectors (max 15 available).")
        sys.exit(1)
    logger.info(f"NDEF message length is {total_length} bytes, requiring {sectors_needed} sector(s).")
    offset = 0
    # Write to sectors 1 to (1+sectors_needed-1)
    for sector in range(1, 1 + sectors_needed):
        chunk = ndef_message[offset:offset+48]
        offset += 48
        chunk = chunk.ljust(48, b'\x00')
        user_blocks = [sector * 4, sector * 4 + 1, sector * 4 + 2]
        for i, block in enumerate(user_blocks):
            data = chunk[i*16:(i+1)*16]
            try_authenticate_block(connection, block, candidate_keys)
            write_block(connection, block, data)
            time.sleep(0.1)
        logger.info(f"Sector {sector} written with 48 bytes of NDEF data.")
    logger.info(f"NDEF message written successfully across sectors 1 to {sector}.")

def format_sector0(connection, candidate_keys):
    """
    Format the user area of sector 0 (blocks 1 and 2) with a fixed pattern.
    Pattern:
      - Bytes 0-1: 14 01
      - Bytes 2-31: alternating 03 and E1.
    """
    buffer = bytearray(32)
    buffer[0] = 0x14
    buffer[1] = 0x01
    for i in range(2, 32):
        buffer[i] = 0x03 if ((i - 2) % 2 == 0) else 0xE1
    logger.debug(f"Formatting Sector 0 user area with pattern: {buffer.hex()}")
    for block, data in zip([1, 2], [buffer[:16], buffer[16:32]]):
        try_authenticate_block(connection, block, candidate_keys)
        write_block(connection, block, data)
        time.sleep(0.1)
    logger.info("Sector 0 user area formatted.")

def format_trailers(connection, candidate_keys):
    """
    Update the trailer block of each sector (0 through 15) with new keys.
    Trailer block format (16 bytes):
       [Key A (6 bytes)] + [Access Bits (4 bytes)] + [Key B (6 bytes)]
    For sector 0, Key A is set to FALLBACK_SECTOR0_KEY.
    For all other sectors, Key A is set to FALLBACK_DEFAULT_KEY.
    """
    for sector in range(0, 16):
        trailer_block = sector * 4 + 3
        if sector == 0:
            new_keyA = FALLBACK_SECTOR0_KEY
        else:
            new_keyA = FALLBACK_DEFAULT_KEY
        trailer_data = bytearray()
        trailer_data.extend(new_keyA)     # Key A (6 bytes)
        trailer_data.extend(ACCESS_BITS)    # Access Bits (4 bytes)
        trailer_data.extend(KEYB_DEFAULT)   # Key B (6 bytes)
        logger.debug(f"Formatting trailer for sector {sector} (block {trailer_block}) with data: {trailer_data.hex()}")
        try_authenticate_block(connection, trailer_block, candidate_keys)
        write_block(connection, trailer_block, trailer_data)
        time.sleep(0.1)
    logger.info("All trailer blocks have been formatted with new keys.")

def main():
    parser = argparse.ArgumentParser(
        description="Write an NDEF URL record to a MIFARE Classic 1K card using candidate keys from keys.txt "
                    "for authentication, and format the tag to match NFC Tools settings. Supports writing NDEF "
                    "messages spanning multiple sectors (max 15 sectors)."
    )
    parser.add_argument("url", help="URL to write")
    parser.add_argument("--no-format", action="store_true",
                        help="Do not format sector 0 or update trailer keys; only write the NDEF message.")
    args = parser.parse_args()

    url = args.url
    logger.info(f"URL to write: {url}")
    ndef_message = construct_ndef(url)
    logger.info(f"Constructed NDEF TLV (hex): {toHexString(list(ndef_message))}")

    # Get candidate keys from keys.txt
    candidate_keys = read_candidate_keys("keys.txt")
    logger.info("Candidate keys: " + ", ".join([toHexString(key) for key in candidate_keys]))

    # Get available smart card readers.
    available_readers = readers()
    if not available_readers:
        logger.error("No smart card readers found.")
        sys.exit(1)
    logger.info("Available readers:")
    for i, rdr in enumerate(available_readers):
        logger.info(f" {i}: {rdr}")
    reader = available_readers[0]
    logger.info(f"Using reader: {reader}")

    # Connect to the card.
    connection = reader.createConnection()
    try:
        connection.connect()
    except Exception as e:
        logger.error(f"Failed to connect to the NFC tag: {e}")
        sys.exit(1)

    # Write the NDEF message into consecutive sectors (starting at sector 1).
    write_ndef_message_multi(connection, ndef_message, candidate_keys)

    if not args.no_format:
        logger.info("Formatting tag (sector 0 and trailer blocks)...")
        format_sector0(connection, candidate_keys)
        format_trailers(connection, candidate_keys)
    else:
        logger.info("--no-format specified; skipping tag formatting.")

    logger.info("Operation complete.")

if __name__ == '__main__':
    main()
