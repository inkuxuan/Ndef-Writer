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
from write_ndef_classic import write_ndef_message_multi, format_sector0, format_trailers
from write_ndef_ultralight import write_ndef_message as write_ndef_message_ultralight
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
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(root, textvariable=self.status_var)
        status_label.pack(pady=5)
        
        # Bulk write state
        self.bulk_write_active = False
        self.bulk_thread = None
        self.current_reader = None
        self.cards_written_count = 0

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
                write_ndef_message_multi(connection, ndef_message, [[0xFF] * 6])  # Default key
                format_sector0(connection, [[0xFF] * 6])
                format_trailers(connection, [[0xFF] * 6])
            
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

def main():
    root = tk.Tk()
    app = NDEFWriterUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
