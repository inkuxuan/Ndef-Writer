#!/usr/bin/env python
"""
UI application for writing NDEF URL records to NFC tags.
Supports both MIFARE Classic and NTAG213 (MIFARE Ultralight) tags.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from ndef_writer_common import construct_ndef, get_reader, wait_for_card
from write_ndef_classic import write_ndef_message_multi, format_sector0, format_trailers, try_authenticate_block, read_candidate_keys
from write_ndef_ultralight import write_ndef_message as write_ndef_message_ultralight, read_page
from smartcard.System import readers

class NDEFWriterUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NDEF URL Writer")
        self.root.geometry("400x200")
        
        # Card type selection
        self.card_type = tk.StringVar(value="NTAG213")
        card_frame = ttk.Frame(root, padding="5")
        card_frame.pack(fill=tk.X)
        ttk.Label(card_frame, text="Card Type:").pack(side=tk.LEFT)
        card_combo = ttk.Combobox(card_frame, textvariable=self.card_type, 
                                 values=["NTAG213", "MIFARE Classic"], state="readonly")
        card_combo.pack(side=tk.LEFT, padx=5)
        
        # URL input
        url_frame = ttk.Frame(root, padding="5")
        url_frame.pack(fill=tk.X)
        ttk.Label(url_frame, text="URL:").pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(root, padding="5")
        button_frame.pack(fill=tk.X)
        self.write_button = ttk.Button(button_frame, text="Write", command=self.write_card)
        self.write_button.pack(side=tk.LEFT, padx=5)
        self.bulk_button = ttk.Button(button_frame, text="Bulk Write", command=self.toggle_bulk_write)
        self.bulk_button.pack(side=tk.LEFT, padx=5)
        self.stress_button = ttk.Button(button_frame, text="Stress Test", command=self.toggle_stress_test)
        self.stress_button.pack(side=tk.LEFT, padx=5)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(root, textvariable=self.status_var)
        status_label.pack(pady=5)
        
        # Bulk write state
        self.bulk_write_active = False
        self.bulk_thread = None
        self.current_reader = None
        self.cards_written_count = 0
        
        # Stress test state
        self.stress_test_active = False
        self.stress_thread = None
        self.stress_read_count = 0

    def write_card(self, from_bulk=False):
        """Write URL to a single card.
        
        Args:
            from_bulk (bool): If True, don't show popup messages (used in bulk mode)
        """
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        self.status_var.set("Waiting for card...")
        reader, connection = get_reader()
        if not reader or not connection:
            self.status_var.set("No reader found")
            return
        
        try:
            ndef_message = construct_ndef(url)
            if self.card_type.get() == "NTAG213":
                write_ndef_message_ultralight(connection, ndef_message)
            else:  # MIFARE Classic
                candidate_keys = read_candidate_keys("keys.txt")
                write_ndef_message_multi(connection, ndef_message, candidate_keys)
                format_sector0(connection, candidate_keys)
                format_trailers(connection, candidate_keys)
            
            if from_bulk:
                self.cards_written_count += 1
                self.status_var.set(f"Write successful - Cards written: {self.cards_written_count}")
            else:
                self.status_var.set("Write successful")
                messagebox.showinfo("Success", "URL written successfully")
        except Exception as e:
            self.status_var.set(f"Write failed: {str(e)}")
            if not from_bulk:
                messagebox.showerror("Error", f"Failed to write URL: {str(e)}")
        finally:
            connection.disconnect()

    def bulk_write_loop(self):
        """Background thread for bulk writing."""
        # Get reader once at the start
        available_readers = readers()
        if not available_readers:
            self.root.after(0, lambda: self.status_var.set("No reader found"))
            return
        
        self.current_reader = available_readers[0]
        self.root.after(0, lambda: self.status_var.set(f"Bulk write active - waiting for cards... (Reader: {self.current_reader})"))
        
        last_card = None
        while self.bulk_write_active:
            try:
                # Try to connect to a card
                connection = self.current_reader.createConnection()
                connection.connect()
                
                # Get card UID to detect card change
                get_uid_apdu = [0xFF, 0xCA, 0x00, 0x00, 0x00]
                response, sw1, sw2 = connection.transmit(get_uid_apdu)
                if (sw1, sw2) == (0x90, 0x00):
                    current_card = bytes(response).hex()
                    
                    # Only write if this is a new card
                    if current_card != last_card:
                        last_card = current_card
                        connection.disconnect()  # Disconnect before writing
                        self.root.after(0, lambda: self.write_card(from_bulk=True))
                        time.sleep(1)  # Wait a bit before next card
                    else:
                        connection.disconnect()
                        time.sleep(0.1)  # Small delay if same card
                else:
                    connection.disconnect()
                    time.sleep(0.1)
            except:
                # No card present, wait a bit
                time.sleep(0.1)

    def toggle_bulk_write(self):
        """Toggle bulk write mode."""
        if not self.bulk_write_active:
            self.bulk_write_active = True
            self.cards_written_count = 0
            self.bulk_button.configure(text="Stop")
            self.write_button.configure(state="disabled")
            self.status_var.set("Initializing bulk write...")
            self.bulk_thread = threading.Thread(target=self.bulk_write_loop)
            self.bulk_thread.daemon = True
            self.bulk_thread.start()
        else:
            self.bulk_write_active = False
            self.bulk_button.configure(text="Bulk Write")
            self.write_button.configure(state="normal")
            self.status_var.set("Ready")
            if self.bulk_thread:
                self.bulk_thread.join(timeout=1.0)
            self.current_reader = None

    def read_card(self):
        """Read NDEF data from a card.
        
        Returns:
            bool: True if read was successful, False otherwise
        """
        self.status_var.set("Reading card...")
        reader, connection = get_reader()
        if not reader or not connection:
            self.status_var.set("No reader found")
            return False
        
        try:
            if self.card_type.get() == "NTAG213":
                # For NTAG213, read the first few pages to verify NDEF data
                # Read capability container (page 3)
                cc_data = read_page(connection, 3)
                if cc_data[0] != 0xE1:  # Check if it's a valid NDEF tag
                    self.status_var.set("Not a valid NDEF tag")
                    return False
                
                # Read first NDEF data page (page 4)
                ndef_data = read_page(connection, 4)
                if ndef_data[0] != 0x03:  # Check if it starts with NDEF TLV tag
                    self.status_var.set("No NDEF message found")
                    return False
                
                return True
            else:  # MIFARE Classic
                # For MIFARE Classic, try to authenticate and read sector 1
                candidate_keys = read_candidate_keys("keys.txt")
                try:
                    # Try to authenticate block 4 (first block of sector 1)
                    key, key_type = try_authenticate_block(connection, 4, candidate_keys)
                    return True
                except Exception as e:
                    self.status_var.set(f"Authentication failed: {str(e)}")
                    return False
        except Exception as e:
            self.status_var.set(f"Read failed: {str(e)}")
            return False
        finally:
            connection.disconnect()
    
    def stress_test_loop(self):
        """Background thread for stress testing (write and read repeatedly)."""
        # Get reader once at the start
        available_readers = readers()
        if not available_readers:
            self.root.after(0, lambda: self.status_var.set("No reader found"))
            return
        
        self.current_reader = available_readers[0]
        self.root.after(0, lambda: self.status_var.set("Stress test active - place a card on the reader"))
        
        url = self.url_entry.get().strip()
        if not url:
            self.root.after(0, lambda: self.status_var.set("Error: Please enter a URL"))
            self.stress_test_active = False
            self.stress_button.configure(text="Stress Test")
            return
        
        while self.stress_test_active:
            try:
                # Try to connect to a card
                connection = self.current_reader.createConnection()
                connection.connect()
                connection.disconnect()
                
                # Card detected, write to it
                self.root.after(0, lambda: self.status_var.set(f"Writing to card... (Successful reads: {self.stress_read_count})"))
                
                # Write to the card
                reader, connection = get_reader()
                if reader and connection:
                    try:
                        ndef_message = construct_ndef(url)
                        if self.card_type.get() == "NTAG213":
                            write_ndef_message_ultralight(connection, ndef_message)
                        else:  # MIFARE Classic
                            candidate_keys = read_candidate_keys("keys.txt")
                            write_ndef_message_multi(connection, ndef_message, candidate_keys)
                        
                        connection.disconnect()
                        time.sleep(0.5)  # Small delay after write
                        
                        # Now try to read it back
                        self.root.after(0, lambda: self.status_var.set(f"Reading from card... (Successful reads: {self.stress_read_count})"))
                        if self.read_card():
                            self.stress_read_count += 1
                            self.root.after(0, lambda: self.status_var.set(f"Read successful - Successful reads: {self.stress_read_count}"))
                        else:
                            self.root.after(0, lambda: self.status_var.set(f"Read failed - Successful reads: {self.stress_read_count}"))
                        
                        time.sleep(1)  # Wait a bit before next cycle
                    except Exception as e:
                        self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)} - Successful reads: {self.stress_read_count}"))
                        time.sleep(1)
            except:
                # No card present, wait a bit
                time.sleep(0.1)
    
    def toggle_stress_test(self):
        """Toggle stress test mode."""
        if not self.stress_test_active:
            # Make sure bulk write is not active
            if self.bulk_write_active:
                self.toggle_bulk_write()
                
            self.stress_test_active = True
            self.stress_read_count = 0
            self.stress_button.configure(text="Stop")
            self.write_button.configure(state="disabled")
            self.bulk_button.configure(state="disabled")
            self.status_var.set("Initializing stress test...")
            self.stress_thread = threading.Thread(target=self.stress_test_loop)
            self.stress_thread.daemon = True
            self.stress_thread.start()
        else:
            self.stress_test_active = False
            self.stress_button.configure(text="Stress Test")
            self.write_button.configure(state="normal")
            self.bulk_button.configure(state="normal")
            self.status_var.set("Ready")
            if self.stress_thread:
                self.stress_thread.join(timeout=1.0)
            self.current_reader = None

def main():
    root = tk.Tk()
    app = NDEFWriterUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
