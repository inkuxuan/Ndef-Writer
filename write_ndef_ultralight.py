#!/usr/bin/env python
"""
A command-line tool to write an NDEF URL record to a NTAG213 (MIFARE Ultralight) tag using
an ACS ACR1251 reader on Windows.

The script writes the NDEF message starting from page 4 (after the capability container),
and handles the capability container configuration automatically.

Requirements:
  - Python 3.x
  - pyscard (install via: pip install pyscard)
"""

import sys
import time
import argparse
import logging
from smartcard.System import readers
from smartcard.util import toHexString

# Set up logging: default level INFO; DEBUG messages hidden unless configured.
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants for APDU commands
PAGE_SIZE = 4  # NTAG213 pages are 4 bytes each
MAX_PAGES = 39  # NTAG213 has 39 pages total
CC_PAGE = 3  # Capability Container is at page 3
NDEF_START_PAGE = 4  # NDEF message starts at page 4

def construct_ndef(url):
    """
    Construct an NDEF TLV for a URL record with prefix abbreviation.
    Returns a bytes object containing the TLV.
    """
    # URL prefix abbreviations (from NDEF URL Record Type Definition)
    url_prefixes = {
        "http://www.": 0x01,
        "https://www.": 0x02,
        "http://": 0x03,
        "https://": 0x04,
        "tel:": 0x05,
        "mailto:": 0x06,
        "ftp://anonymous:anonymous@": 0x07,
        "ftp://ftp.": 0x08,
        "ftps://": 0x09,
        "sftp://": 0x0A,
        "smb://": 0x0B,
        "nfs://": 0x0C,
        "ftp://": 0x0D,
        "dav://": 0x0E,
        "news:": 0x0F,
        "telnet://": 0x10,
        "imap:": 0x11,
        "rtsp://": 0x12,
        "urn:": 0x13,
        "pop:": 0x14,
        "sip:": 0x15,
        "sips:": 0x16,
        "tftp:": 0x17,
        "btspp://": 0x18,
        "btl2cap://": 0x19,
        "btgoep://": 0x1A,
        "tcpobex://": 0x1B,
        "irdaobex://": 0x1C,
        "file://": 0x1D,
        "urn:epc:id:": 0x1E,
        "urn:epc:tag:": 0x1F,
        "urn:epc:pat:": 0x20,
        "urn:epc:raw:": 0x21,
        "urn:epc:": 0x22,
        "urn:nfc:": 0x23
    }

    # Find the longest matching prefix
    prefix_code = 0x00  # Default: no prefix
    remaining_url = url
    for prefix, code in url_prefixes.items():
        if url.startswith(prefix):
            prefix_code = code
            remaining_url = url[len(prefix):]
            break

    # Construct the payload with prefix code
    payload = bytes([prefix_code]) + remaining_url.encode('utf-8')
    
    # Construct the NDEF record
    header = bytes([0xD1])  # MB=1, ME=1, CF=0, SR=1, IL=0, TNF=1
    type_length = bytes([0x01])  # for 'U'
    payload_length = bytes([len(payload)])
    record_type = b'U'
    ndef_record = header + type_length + payload_length + record_type + payload
    
    # Add TLV wrapper
    tlv = bytes([0x03, len(ndef_record)]) + ndef_record + bytes([0xFE])
    return tlv

def read_page(connection, page):
    """
    Read a 4-byte page from the tag.
    APDU: FF B0 00 <page> 04
    """
    apdu = [0xFF, 0xB0, 0x00, page, 0x04]
    logger.debug(f"Reading page {page}")
    response, sw1, sw2 = connection.transmit(apdu)
    if (sw1, sw2) != (0x90, 0x00):
        logger.error(f"Error reading page {page}: SW1={sw1:02X}, SW2={sw2:02X}")
        sys.exit(1)
    return bytes(response)

def write_page(connection, page, data):
    """
    Write 4 bytes to a page.
    APDU: FF D6 00 <page> 04 <4 bytes>
    """
    if len(data) != 4:
        logger.error(f"Data must be exactly 4 bytes for page write")
        sys.exit(1)
    apdu = [0xFF, 0xD6, 0x00, page, 0x04] + list(data)
    logger.debug(f"Writing page {page}: {toHexString(list(data))}")
    response, sw1, sw2 = connection.transmit(apdu)
    if (sw1, sw2) != (0x90, 0x00):
        logger.error(f"Error writing page {page}: SW1={sw1:02X}, SW2={sw2:02X}")
        sys.exit(1)

def write_ndef_message(connection, ndef_message):
    """
    Write the NDEF message to the tag, starting from page 4.
    Also configures the Capability Container (page 3) appropriately.
    """
    # Configure Capability Container
    cc_data = bytes([0xE1, 0x10, 0x12, 0x00])  # E1=NDEF, 10=Version 1.0, 12=12h bytes available, 00=Read/Write
    write_page(connection, CC_PAGE, cc_data)
    logger.info("Capability Container configured")

    # Write NDEF message in 4-byte chunks
    total_length = len(ndef_message)
    pages_needed = (total_length + 3) // 4  # Ceiling division
    if pages_needed > (MAX_PAGES - NDEF_START_PAGE):
        logger.error(f"NDEF message too long: requires {pages_needed} pages (max {MAX_PAGES - NDEF_START_PAGE} available)")
        sys.exit(1)

    logger.info(f"NDEF message length is {total_length} bytes, requiring {pages_needed} pages")
    
    # Pad the message to a multiple of 4 bytes
    padded_message = ndef_message.ljust(pages_needed * 4, b'\x00')
    
    # Write each page
    for i in range(pages_needed):
        page_data = padded_message[i*4:(i+1)*4]
        write_page(connection, NDEF_START_PAGE + i, page_data)
        time.sleep(0.1)  # Small delay between writes
    
    logger.info(f"NDEF message written successfully to pages {NDEF_START_PAGE} to {NDEF_START_PAGE + pages_needed - 1}")

def main():
    parser = argparse.ArgumentParser(
        description="Write an NDEF URL record to a NTAG213 (MIFARE Ultralight) tag"
    )
    parser.add_argument("url", help="URL to write")
    args = parser.parse_args()

    url = args.url
    logger.info(f"URL to write: {url}")
    ndef_message = construct_ndef(url)
    logger.info(f"Constructed NDEF TLV (hex): {toHexString(list(ndef_message))}")

    # Get available smart card readers
    available_readers = readers()
    if not available_readers:
        logger.error("No smart card readers found")
        sys.exit(1)
    
    logger.info("Available readers:")
    for i, rdr in enumerate(available_readers):
        logger.info(f" {i}: {rdr}")
    
    reader = available_readers[0]
    logger.info(f"Using reader: {reader}")

    # Connect to the card
    connection = reader.createConnection()
    try:
        connection.connect()
    except Exception as e:
        logger.error(f"Failed to connect to the NFC tag: {e}")
        sys.exit(1)

    # Write the NDEF message
    write_ndef_message(connection, ndef_message)
    logger.info("Operation complete")

if __name__ == '__main__':
    main() 