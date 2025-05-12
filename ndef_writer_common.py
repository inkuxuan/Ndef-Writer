#!/usr/bin/env python
"""
Common functionality for writing NDEF URL records to NFC tags.
"""

import sys
import logging
from smartcard.System import readers
from smartcard.util import toHexString

# Set up logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

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

def get_reader():
    """
    Get the first available smart card reader.
    Returns (reader, connection) tuple or (None, None) if no reader is found.
    """
    available_readers = readers()
    if not available_readers:
        logger.error("No smart card readers found")
        return None, None
    
    reader = available_readers[0]
    logger.info(f"Using reader: {reader}")
    
    connection = reader.createConnection()
    try:
        connection.connect()
        return reader, connection
    except Exception as e:
        logger.error(f"Failed to connect to the NFC tag: {e}")
        return None, None

def wait_for_card(reader):
    """
    Wait for a card to be presented to the reader.
    Returns True if a card is detected, False if an error occurs.
    """
    try:
        connection = reader.createConnection()
        connection.connect()
        connection.disconnect()
        return True
    except:
        return False 