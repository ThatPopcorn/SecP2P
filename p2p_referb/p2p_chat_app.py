# p2p_chat_app.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, font as tkFont, PanedWindow
import socket
import threading
import json
import queue
import time
import os
import logging
import collections

# Import cryptographic functions
import crypto_utils

# --- Color Constants --- (Keep as before)
COLOR_DARK_BG = "#2E2E2E"       # Dark grey background
COLOR_MEDIUM_BG = "#3C3C3C"     # Slightly lighter grey for fields/buttons
COLOR_LIGHT_BG = "#4A4A4A"      # Hover/active background
COLOR_DARK_FG = "#A9A9A9"       # Darker foreground for less emphasis (timestamps)
COLOR_LIGHT_FG = "#E0E0E0"      # Main light foreground (off-white)
COLOR_ACCENT = "#007ACC"       # Blue accent for highlights/status
COLOR_ACCENT_FG = "#FFFFFF"      # Text on accent background
COLOR_GREEN = "#4CAF50"        # Success/Ready status / Peer messages
COLOR_YELLOW = "#FFC107"       # Waiting/Verification status
COLOR_ORANGE = "#FF9800"       # Disconnected/Warning status
COLOR_RED = "#F44336"          # Error/Block status
COLOR_PURPLE = "#9C27B0"       # System messages

# --- Constants ---
DEFAULT_PORT = 65001
BUFFER_SIZE = 4096
LOG_FILE = "chat_audit.log"
APP_NAME = "Secure P2P Chat"

# --- Application States ---
STATE_INITIAL = "INITIAL"
STATE_WAITING_FOR_CONNECTION = "WAITING_FOR_CONNECTION"
STATE_CONNECTING = "CONNECTING"
STATE_WAITING_FOR_KEYS = "WAITING_FOR_KEYS"
STATE_VERIFYING_KEYS = "VERIFYING_KEYS" # Generic state for verification (SAS or TOFU fail)
STATE_CHAT_READY = "CHAT_READY"
STATE_DISCONNECTED = "DISCONNECTED"
STATE_ERROR = "ERROR"

# --- SAS Verification Dialog ---
class SASVerificationDialog(tk.Toplevel):
    """Custom modal dialog for SAS verification."""
    def __init__(self, parent, sas_string, callback):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.title("!! VERIFY SESSION !!")
        self.callback = callback # Function to call with result ('match', 'mismatch')

        self.config(bg=COLOR_DARK_BG)
        style = ttk.Style(self)
        try: style.theme_use('clam')
        except tk.TclError: style.theme_use('default')

        style.configure('Toplevel', background=COLOR_DARK_BG)
        main_frame = ttk.Frame(self, padding="15 15 15 15", style='Dialog.TFrame')
        main_frame.pack(expand=True, fill=tk.BOTH)

        normal_font = tkFont.Font(family="Segoe UI", size=9)
        sas_font = tkFont.Font(family="Consolas", size=14, weight="bold")

        # Re-use styles from VerificationDialog where possible
        style.configure('Dialog.TFrame', background=COLOR_DARK_BG)
        style.configure('Norm.TLabel', background=COLOR_DARK_BG, foreground=COLOR_LIGHT_FG, font=normal_font)
        style.configure('SAS.TLabel', background=COLOR_DARK_BG, foreground=COLOR_YELLOW, font=sas_font) # Yellow SAS
        style.configure('Match.TButton', foreground=COLOR_ACCENT_FG, background=COLOR_GREEN, font=normal_font, padding=5)
        style.map('Match.TButton', background=[('active', '#388E3C')])
        style.configure('Mismatch.TButton', foreground=COLOR_ACCENT_FG, background=COLOR_RED, font=normal_font, padding=5)
        style.map('Mismatch.TButton', background=[('active', '#D32F2F')])

        ttk.Label(main_frame, text="Compare this Short Authentication String (SAS)\nwith your peer via a separate, trusted channel\n(e.g., phone call, in person):",
                  style='Norm.TLabel', justify=tk.CENTER).pack(pady=(0, 10))

        ttk.Label(main_frame, text=sas_string, style='SAS.TLabel', relief='solid', borderwidth=1, padding=8).pack(pady=10)

        ttk.Label(main_frame, text="Do the numbers/words match EXACTLY?", style='Norm.TLabel').pack(pady=(10, 5))

        button_frame = ttk.Frame(main_frame, style='Dialog.TFrame')
        button_frame.pack(pady=(10, 0))

        match_button = ttk.Button(button_frame, text="MATCH", command=self.on_match, style="Match.TButton", width=12)
        match_button.pack(side=tk.LEFT, padx=10)
        mismatch_button = ttk.Button(button_frame, text="MISMATCH", command=self.on_mismatch, style="Mismatch.TButton", width=12)
        mismatch_button.pack(side=tk.LEFT, padx=10)

        self.protocol("WM_DELETE_WINDOW", self.on_mismatch) # Treat closing as mismatch
        self.update_idletasks()

        parent_x = parent.winfo_rootx(); parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width(); parent_height = parent.winfo_height()
        dialog_width = self.winfo_width(); dialog_height = self.winfo_height()
        x = parent_x + (parent_width // 2) - (dialog_width // 2)
        y = parent_y + (parent_height // 3) - (dialog_height // 2)
        self.geometry(f'+{x}+{y}')
        self.focus_set()

    def on_match(self):
        self.grab_release(); self.destroy(); self.callback('match')

    def on_mismatch(self):
        self.grab_release(); self.destroy(); self.callback('mismatch')


class P2PChatApp:
    def __init__(self, root):
        # ... (Initialize root, logging, styles) ...
        self.root = root; self.root.title(APP_NAME); self.root.geometry("750x550"); self.root.minsize(550, 400); self.root.configure(bg=COLOR_DARK_BG) # Slightly adjusted size
        self.setup_logging(); self.logger.info(f"--- {APP_NAME} Started ---")
        self.style = ttk.Style();
        try: self.style.theme_use('clam')
        except tk.TclError: 
            try: 
                self.style.theme_use('alt') 
            except tk.TclError: 
                self.style.theme_use('default')
        # --- Initialize state variables --- (Same as the last full version - NO TOFU)
        try: 
            self.my_signing_priv, self.my_signing_pub = crypto_utils.generate_signing_keys()
            self.my_fingerprint = crypto_utils.get_fingerprint(crypto_utils.serialize_public_key(self.my_signing_pub))
            assert self.my_fingerprint
        except Exception as e: 
            self.logger.critical(f"Failed key init: {e}", exc_info=True)
            messagebox.showerror("Fatal Error", f"Key init error: {e}.")
            self.root.destroy(); self.is_running = False
            return

        self.my_exchange_priv = None
        self.my_exchange_pub = None
        self.peer_signing_pub_bytes = None
        self.peer_exchange_pub = None
        self.shared_secret = None
        self.provisional_shared_secret = None
        self.peer_fingerprint_current = None
        self.key_exchange_nonce = None
        self.send_counter = 0
        self.receive_counter = 0
        self.current_sas_string = None
        self.dhr_self_priv = None
        self.dhr_self_pub_obj = None
        self.dhr_peer_pub = None
        self.rk = None
        self.cks = None
        self.ckr = None
        self.ns = 0
        self.nr = 0
        self.pnr = 0
        self.mkskipped = collections.OrderedDict()
        self.peer_socket = None
        self.server_socket = None
        self.listen_thread = None
        self.receive_thread = None
        self.is_running = True
        self.state = STATE_INITIAL
        self.connection_role = "None"
        self.blocked_fingerprints = set()
        self.peer_address = None
        self.peer_is_ready = False
        self.local_is_ready = False

        self.ip_entry = None
        self.port_entry = None
        self.host_button = None
        self.connect_button = None
        self.role_label = None
        self.my_fp_label = None
        self.peer_fp_label = None
        self.security_label = None
        self.peer_addr_label = None
        self.chat_history = None
        self.message_entry = None
        self.send_button = None
        self.status_label = None

        # --- Configure Styles (BEFORE creating widgets) ---
        self.configure_styles()
        # --- UI Creation ---
        self.create_widgets()
        # --- Message Queue & Shutdown ---
        self.ui_queue = queue.Queue(); self.check_queue(); self.root.protocol("WM_DELETE_WINDOW", self.on_closing); self.update_ui_state(STATE_INITIAL)

    # --- UI & Logging Methods --- (configure_styles, create_widgets, setup_logging, add_message_to_history - largely unchanged, ensure no nickname label)
    def configure_styles(self): # ... (Same as previous) ...
        self.style.configure('.', background=COLOR_DARK_BG, foreground=COLOR_LIGHT_FG, fieldbackground=COLOR_MEDIUM_BG, insertcolor=COLOR_LIGHT_FG, borderwidth=1, font=('Segoe UI', 9))
        self.style.map('.', background=[('active', COLOR_LIGHT_BG), ('disabled', COLOR_MEDIUM_BG)], foreground=[('disabled', COLOR_DARK_FG)])
        self.style.configure('TFrame', background=COLOR_DARK_BG)
        self.style.configure('TLabel', background=COLOR_DARK_BG, foreground=COLOR_LIGHT_FG, padding=2)
        self.style.configure('Header.TLabel', font=('Segoe UI', 10, 'bold'), foreground=COLOR_ACCENT)
        self.style.configure('Data.TLabel', font=('Consolas', 9), foreground=COLOR_LIGHT_FG)
        self.style.configure('Status.TLabel', font=('Segoe UI', 9), padding=3)
        self.style.configure('TLabelframe', background=COLOR_DARK_BG, relief='groove', borderwidth=1)
        self.style.configure('TLabelframe.Label', background=COLOR_DARK_BG, foreground=COLOR_LIGHT_FG, font=('Segoe UI', 9, 'italic'))
        self.style.configure('TButton', background=COLOR_MEDIUM_BG, foreground=COLOR_LIGHT_FG, padding=(8, 4), relief='raised')
        self.style.map('TButton', background=[('active', COLOR_LIGHT_BG), ('!disabled', COLOR_MEDIUM_BG)], relief=[('pressed', 'sunken'), ('!pressed', 'raised')])
        self.style.configure('Accent.TButton', background=COLOR_ACCENT, foreground=COLOR_ACCENT_FG)
        self.style.map('Accent.TButton', background=[('active', '#005A9E'), ('!disabled', COLOR_ACCENT)])
        self.style.configure('TEntry', foreground=COLOR_LIGHT_FG, fieldbackground=COLOR_MEDIUM_BG, relief='flat')
        self.style.configure('TPanedwindow', background=COLOR_DARK_BG)
        self.style.configure('Sash', background=COLOR_MEDIUM_BG, borderwidth=1, relief='raised')

    def create_widgets(self):
        """Create all UI elements with a cleaner, more compact layout."""

        # --- Top Connection Bar --- (Reduced padding)
        top_frame = ttk.Frame(self.root, padding="3 3 3 3", style='TFrame')
        top_frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(top_frame, text="Peer IP:", style='TLabel').pack(side=tk.LEFT, padx=(3, 0))
        self.ip_entry = ttk.Entry(top_frame, width=15, style='TEntry', font=('Segoe UI', 9)) # Ensure font matches
        self.ip_entry.pack(side=tk.LEFT, padx=3)
        self.ip_entry.insert(0, "127.0.0.1")

        ttk.Label(top_frame, text="Port:", style='TLabel').pack(side=tk.LEFT, padx=(3, 0))
        self.port_entry = ttk.Entry(top_frame, width=7, style='TEntry', font=('Segoe UI', 9))
        self.port_entry.pack(side=tk.LEFT, padx=3)
        self.port_entry.insert(0, str(DEFAULT_PORT))

        self.host_button = ttk.Button(top_frame, text="Host", command=self.start_hosting, width=6, style='TButton') # Smaller width
        self.host_button.pack(side=tk.LEFT, padx=3)

        self.connect_button = ttk.Button(top_frame, text="Connect", command=self.start_connecting, width=9, style='TButton') # Smaller width
        self.connect_button.pack(side=tk.LEFT, padx=3)

        # --- Main Area (Paned Window) ---
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.FLAT, # Flat sash
                                   bg=COLOR_DARK_BG, bd=0, sashwidth=4, showhandle=False) # Thinner sash, no handle
        main_pane.pack(fill=tk.BOTH, expand=True, padx=3, pady=3) # Reduced padding

        # --- Left: Info Panel (Using pack and separators) ---
        info_area_frame = ttk.Frame(main_pane, width=200, style='TFrame') # Reduced initial width slightly
        info_area_frame.pack_propagate(False)
        main_pane.add(info_area_frame, minsize=160) # Reduced minsize

        # Helper function to create label pairs
        def create_info_row(parent, label_text, var_name, initial_value="N/A", data_style='Data.TLabel'):
            row_frame = ttk.Frame(parent, style='TFrame')
            ttk.Label(row_frame, text=label_text, style='Header.TLabel', width=8, anchor='w').pack(side=tk.LEFT, padx=(3, 1)) # Fixed width header
            data_label = ttk.Label(row_frame, text=initial_value, style=data_style, anchor='w', wraplength=120) # Tighter wraplength
            data_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(1, 3))
            setattr(self, var_name, data_label) # Store ref
            row_frame.pack(fill=tk.X, pady=(1, 0)) # Pack row with minimal vertical padding
            return data_label

        create_info_row(info_area_frame, "Role:", 'role_label', self.connection_role.capitalize())
        self.my_fp_label = create_info_row(info_area_frame, "Your FP:", 'my_fp_label', self.my_fingerprint)
        self.peer_fp_label = create_info_row(info_area_frame, "Peer FP:", 'peer_fp_label')
        ttk.Separator(info_area_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=3, padx=3)
        self.security_label = create_info_row(info_area_frame, "Security:", 'security_label', "Not Connected")
        self.peer_addr_label = create_info_row(info_area_frame, "Peer Addr:", 'peer_addr_label')

        # Set initial colors
        self.my_fp_label.config(foreground=COLOR_GREEN)
        self.peer_fp_label.config(foreground=COLOR_DARK_FG)
        self.security_label.config(foreground=COLOR_ORANGE)
        self.peer_addr_label.config(foreground=COLOR_DARK_FG)

        # --- Right: Chat Area ---
        chat_area_frame = ttk.Frame(main_pane, style='TFrame')
        main_pane.add(chat_area_frame)

        # Chat History (Reduced padding)
        self.chat_history = scrolledtext.ScrolledText(chat_area_frame, wrap=tk.WORD, state=tk.DISABLED, height=10, # Height adjusted by packing
                                                      bg=COLOR_MEDIUM_BG, fg=COLOR_LIGHT_FG, relief=tk.FLAT, borderwidth=1, padx=3, pady=3, # Reduced padding
                                                      font=("Segoe UI", 9), insertbackground=COLOR_LIGHT_FG) # Slightly smaller font
        self.chat_history.pack(fill=tk.BOTH, expand=True, padx=0, pady=0) # No external padding

        # Configure tags (Adjust font size if needed)
        self.chat_history.tag_config('self', foreground=COLOR_ACCENT, justify='right', font=("Segoe UI", 9, 'bold'))
        self.chat_history.tag_config('peer', foreground=COLOR_GREEN, justify='left', font=("Segoe UI", 9))
        self.chat_history.tag_config('system', foreground=COLOR_PURPLE, justify='center', font=('Segoe UI', 8, 'italic'))
        self.chat_history.tag_config('error', foreground=COLOR_RED, justify='center', font=('Segoe UI', 8, 'bold'))
        self.chat_history.tag_config('warning', foreground=COLOR_ORANGE, justify='center', font=('Segoe UI', 8, 'italic'))
        self.chat_history.tag_config('timestamp', foreground=COLOR_DARK_FG, font=('Segoe UI', 7)) # Smaller timestamp

        # Input Area (Reduced padding)
        input_frame = ttk.Frame(chat_area_frame, padding="3 3 3 3", style='TFrame') # Reduced padding
        input_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.message_entry = ttk.Entry(input_frame, font=("Segoe UI", 9), style='TEntry')
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 3))
        self.message_entry.bind("<Return>", self.send_message_event)
        self.message_entry.config(state=tk.DISABLED)

        self.send_button = ttk.Button(input_frame, text="Send", command=self.send_message_event, style='Accent.TButton', width=6) # Smaller width
        self.send_button.pack(side=tk.RIGHT)
        self.send_button.config(state=tk.DISABLED)

        # --- Bottom Status Bar (Separator + Label) ---
        status_frame = ttk.Frame(self.root, style='TFrame')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Separator(status_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=3) # Separator line
        self.status_label = ttk.Label(status_frame, text="Status: Initialized", style='Status.TLabel', anchor='w') # Flat label
        self.status_label.pack(fill=tk.X, padx=3, pady=(1,1)) # Minimal padding

    def setup_logging(self): # ... (Same as previous) ...
        self.logger = logging.getLogger(APP_NAME); self.logger.setLevel(logging.INFO)
        if self.logger.hasHandlers(): self.logger.handlers.clear()
        log_format = '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'; formatter = logging.Formatter(log_format)
        try: file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8'); file_handler.setFormatter(formatter); self.logger.addHandler(file_handler)
        except IOError as e: print(f"Error: Could not open log file '{LOG_FILE}': {e}."); self.logger.error(f"Failed to initialize file logging: {e}")
        console_handler = logging.StreamHandler(); console_handler.setFormatter(formatter); self.logger.addHandler(console_handler)
        self.logger.propagate = False; crypto_logger = logging.getLogger('crypto_utils'); crypto_logger.setLevel(logging.INFO)
        if not crypto_logger.hasHandlers(): crypto_logger.addHandler(file_handler); crypto_logger.addHandler(console_handler)
        crypto_logger.propagate = False

    def add_message_to_history(self, message, tag='peer'): # ... (Same as previous) ...
        if not self.is_running: return
        try:
            if not self.chat_history or not self.chat_history.winfo_exists(): return
            self.chat_history.config(state=tk.NORMAL); timestamp = time.strftime("%H:%M:%S")
            self.chat_history.insert(tk.END, f"[{timestamp}] ", 'timestamp'); self.chat_history.insert(tk.END, f"{message}\n", tag)
            self.chat_history.config(state=tk.DISABLED); self.chat_history.see(tk.END)
        except tk.TclError as e: self.logger.warning(f"TclError adding message to history: {e}")
        except Exception as e: self.logger.exception("Unexpected error adding message to history.")


    # --- State Management & Reset ---
    def reset_crypto_session(self):
        """Resets all session-specific crypto and state variables."""
        self.logger.info("Resetting ALL crypto session state.")
        # Initial exchange vars
        self.peer_signing_pub_bytes = None
        self.peer_exchange_pub = None
        self.key_exchange_nonce = None
        self.provisional_shared_secret = None
        self.peer_fingerprint_current = None
        self.current_sas_string = None
        # Double Ratchet vars
        self.dhr_self_priv = None
        self.dhr_self_pub = None
        self.dhr_peer_pub = None
        self.rk = None
        self.cks = None
        self.ckr = None
        self.ns = 0
        self.nr = 0
        self.pnr = 0
        self.mkskipped.clear()
        # Other state vars
        self.peer_address = None
        self.peer_is_ready = False
        self.local_is_ready = False


    def update_ui_state(self, new_state):
        """Updates the entire UI based on the new application state."""
        # ... (Mostly same as previous simplified version, ensure security text reflects DR) ...
        if not self.is_running: return
        if self.state != new_state: self.logger.info(f"State changing: {self.state} -> {new_state}"); self.state = new_state
        else: self.logger.debug(f"Refreshing UI for state: {self.state}")
        # Info Panel
        self.role_label.config(text=self.connection_role.capitalize()); self.my_fp_label.config(text=self.my_fingerprint if self.my_fingerprint else "Error"); self.peer_fp_label.config(text=self.peer_fingerprint_current if self.peer_fingerprint_current else "N/A")
        if self.peer_address: addr_text = f"{self.peer_address[0]}:{self.peer_address[1]}"; self.peer_addr_label.config(text=addr_text, foreground=COLOR_LIGHT_FG)
        else: self.peer_addr_label.config(text="N/A", foreground=COLOR_DARK_FG)
        # Widget Enables
        can_connect = new_state in [STATE_INITIAL, STATE_DISCONNECTED, STATE_ERROR]; self.host_button.config(state=tk.NORMAL if can_connect else tk.DISABLED); self.connect_button.config(state=tk.NORMAL if can_connect else tk.DISABLED); self.ip_entry.config(state=tk.NORMAL if can_connect else tk.DISABLED); self.port_entry.config(state=tk.NORMAL if can_connect else tk.DISABLED)
        self.message_entry.config(state=tk.DISABLED); self.send_button.config(state=tk.DISABLED)
        # Dynamic Labels
        status_text = "Status: "; status_color = COLOR_LIGHT_FG; security_text = "N/A"; security_color = COLOR_ORANGE; peer_fp_color = COLOR_DARK_FG
        if new_state == STATE_INITIAL: status_text += "Initialized."; security_text = "Not Connected"
        elif new_state == STATE_WAITING_FOR_CONNECTION: ip, port = self.ip_entry.get(), self.port_entry.get(); status_text += f"Listening on {ip}:{port}..."; status_color = COLOR_ACCENT; security_text = "Listening..."; security_color = COLOR_ACCENT
        elif new_state == STATE_CONNECTING: ip, port = self.ip_entry.get(), self.port_entry.get(); status_text += f"Connecting to {ip}:{port}..."; status_color = COLOR_ACCENT; security_text = "Connecting..."; security_color = COLOR_ACCENT
        elif new_state == STATE_WAITING_FOR_KEYS: status_text += "Connected. Exchanging keys..."; status_color = COLOR_YELLOW; security_text = "Key Exchange..."; security_color = COLOR_YELLOW
        elif new_state == STATE_VERIFYING_KEYS: status_text += "!! ACTION REQUIRED: Verify Short Authentication String (SAS) !!"; security_text = "!! VERIFYING (SAS) !!"; status_color = COLOR_RED; security_color = COLOR_RED; peer_fp_color = COLOR_YELLOW; self.peer_fp_label.config(text=self.peer_fingerprint_current if self.peer_fingerprint_current else "Error")
        elif new_state == STATE_CHAT_READY:
            if self.local_is_ready and self.peer_is_ready: status_text += "Secure session active."; status_color = COLOR_GREEN
            else: status_text += "Secure session established. Waiting for peer..."; status_color = COLOR_YELLOW
            security_text = "Encrypted (Double Ratchet)" # Update text
            security_color = COLOR_GREEN; peer_fp_color = COLOR_GREEN
            self.peer_fp_label.config(text=self.peer_fingerprint_current if self.peer_fingerprint_current else "Verified!")
            self.check_and_enable_chat() # Check if chat can be enabled
        elif new_state == STATE_DISCONNECTED: status_text += "Peer disconnected."; status_color = COLOR_ORANGE; security_text = "Disconnected"; security_color = COLOR_ORANGE; self.peer_fp_label.config(text="N/A"); self.peer_fingerprint_current = None; self.peer_is_ready = False; self.local_is_ready = False; self.reset_crypto_session()
        elif new_state == STATE_ERROR: status_text += "Error occurred."; status_color = COLOR_RED; security_text = "Error State"; security_color = COLOR_RED; self.peer_fp_label.config(text="N/A"); self.peer_fingerprint_current = None; self.peer_is_ready = False; self.local_is_ready = False; self.reset_crypto_session()
        # Apply updates - don't overwrite final status if chat is fully ready
        if not (new_state == STATE_CHAT_READY and self.local_is_ready and self.peer_is_ready):
            self.status_label.config(text=status_text, foreground=status_color)
        self.security_label.config(text=security_text, foreground=security_color); self.peer_fp_label.config(foreground=peer_fp_color)


    def check_queue(self):
        """Periodically check the queue for messages from other threads."""
        # ... (Modified version - removed nickname/TOFU handlers) ...
        if not self.is_running: return
        try:
            while True:
                message_data = self.ui_queue.get_nowait(); msg_type = message_data.get("type"); payload = message_data.get("payload")
                self.logger.debug(f"UI Queue Processing: Type={msg_type}")
                if msg_type == "add_message": self.add_message_to_history(payload["message"], payload["tag"])
                elif msg_type == "set_state": self.update_ui_state(payload)
                elif msg_type == "show_sas_dialog": self.show_sas_verification_popup(payload["sas_string"])
                elif msg_type == "connection_failed": messagebox.showerror("Connection Failed", payload, parent=self.root); self.logger.error(f"Connection failed: {payload}"); self.update_ui_state(STATE_ERROR)
                elif msg_type == "connection_lost": self.logger.warning(f"Connection lost: {payload}"); self.add_message_to_history(f"Connection lost: {payload}", "warning"); self.update_ui_state(STATE_DISCONNECTED)
                elif msg_type == "error": messagebox.showerror("Error", payload, parent=self.root); self.logger.error(f"Application error: {payload}"); self.update_ui_state(STATE_ERROR)
                elif msg_type == "update_peer_address": self.peer_address = payload; self.update_ui_state(self.state)
                elif msg_type == "enable_chat_widgets": self.logger.info("Enabling chat widgets via queue."); self.message_entry.config(state=tk.NORMAL); self.send_button.config(state=tk.NORMAL); self.message_entry.focus()
                elif msg_type == "update_status": self.status_label.config(text=payload.get("text", "Status: N/A"), foreground=payload.get("color", COLOR_LIGHT_FG))
                elif msg_type == "check_enable_chat_trigger": self.logger.debug("Check enable chat triggered via queue."); self.check_and_enable_chat()
                elif msg_type == "trigger_auth_completion": self.logger.debug("Completing session authentication triggered via queue."); self.complete_session_authentication()
        except queue.Empty: pass
        except Exception as e: self.logger.exception("Error processing UI queue.")
        finally:
            if self.is_running: self.root.after(100, self.check_queue)


    # --- Network Methods --- (start_hosting, accept_connection, start_connecting, attempt_connection, send_data, start_receive_thread, receive_loop, handle_disconnect - largely unchanged)
    def start_hosting(self): # ... (Same as simplified version) ...
        self.connection_role = 'host'; self.peer_is_ready = False; self.local_is_ready = False; self.update_ui_state(STATE_WAITING_FOR_CONNECTION)
        host = self.ip_entry.get().strip(); port_str = self.port_entry.get()
        try: port = int(port_str); assert 0 < port < 65536
        except (ValueError, AssertionError): messagebox.showerror("Invalid Port", "Port must be 1-65535.", parent=self.root); return
        self.add_message_to_history(f"Starting server on {host}:{port}...", 'system'); self.logger.info(f"Hosting on {host}:{port}. FP: {self.my_fingerprint}")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try: 
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port)); self.server_socket.listen(1)
            self.listen_thread = threading.Thread(target=self.accept_connection, name="AcceptThread", daemon=True)
            self.listen_thread.start()
        except OSError as e: err_msg=f"Error hosting: {e}"; self.add_message_to_history(err_msg, 'error'); self.logger.error(err_msg); self.ui_queue.put({"type": "set_state", "payload": STATE_ERROR}); self.server_socket.close(); self.server_socket = None

    def accept_connection(self): # ... (Same as simplified version) ...
        if not self.server_socket: self.logger.error("Accept called but server socket invalid."); return
        try: 
            self.logger.info(f"Listening on {self.server_socket.getsockname()}...")
            peer_socket, addr = self.server_socket.accept(); peer_socket.settimeout(None)
            self.peer_socket = peer_socket
            self.peer_address = addr; self.ui_queue.put({"type": "update_peer_address", "payload": addr})
            self.logger.info(f"Accepted connection from {addr}")
            self.ui_queue.put({"type": "add_message", "payload": {"message": f"Peer connected from {addr[0]}:{addr[1]}", "tag": "system"}})
            self.server_socket.close(); self.server_socket = None; self.logger.info("Server socket closed.")
            self.start_receive_thread(); self.initiate_key_exchange()
        except OSError as e:
             if self.is_running and self.state == STATE_WAITING_FOR_CONNECTION: err_msg = f"Accept error: {e}"; self.logger.error(err_msg); self.ui_queue.put({"type": "error", "payload": err_msg})
             else: self.logger.warning(f"Accept OSError ignored: {e}")
        except Exception as e:
             if self.is_running: err_msg = f"Unexpected accept error: {e}"; self.logger.exception(err_msg); self.ui_queue.put({"type": "error", "payload": err_msg})
        finally:
             if self.server_socket: self.logger.warning("Closing server socket in accept finally."); self.server_socket.close(); self.server_socket = None

    def start_connecting(self): # ... (Same as simplified version) ...
        self.connection_role = 'client'; self.peer_is_ready = False; self.local_is_ready = False; self.update_ui_state(STATE_CONNECTING)
        host = self.ip_entry.get().strip(); port_str = self.port_entry.get()
        try: port = int(port_str); assert 0 < port < 65536; assert host
        except (ValueError, AssertionError): messagebox.showerror("Invalid Input", "Host IP and Port (1-65535) required.", parent=self.root); return
        self.add_message_to_history(f"Connecting to {host}:{port}...", 'system'); self.logger.info(f"Connecting to {host}:{port}. FP: {self.my_fingerprint}")
        connect_thread = threading.Thread(target=self.attempt_connection, args=(host, port), name="ConnectThread", daemon=True); connect_thread.start()

    def attempt_connection(self, host, port): # ... (Same as simplified version) ...
        client_socket = None
        try: 
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM); client_socket.settimeout(15)
            client_socket.connect((host, port)); client_socket.settimeout(None)
            self.peer_socket = client_socket; self.peer_address = client_socket.getpeername()
            self.ui_queue.put({"type": "update_peer_address", "payload": self.peer_address})
            self.logger.info(f"Connected to {host}:{port}")
            self.ui_queue.put({"type": "add_message", "payload": {"message": f"Connected to {host}:{port}.", "tag": "system"}}); self.start_receive_thread(); self.ui_queue.put({"type": "set_state", "payload": STATE_WAITING_FOR_KEYS})
        except socket.timeout: err_msg=f"Timeout connecting to {host}:{port}."; self.logger.warning(err_msg); self.ui_queue.put({"type": "connection_failed", "payload": err_msg});
        except ConnectionRefusedError: err_msg=f"Connection refused by {host}:{port}."; self.logger.warning(err_msg); self.ui_queue.put({"type": "connection_failed", "payload": err_msg});
        except OSError as e: err_msg=f"Network error connecting: {e}"; self.logger.error(err_msg); self.ui_queue.put({"type": "connection_failed", "payload": err_msg});
        except Exception as e: err_msg=f"Unexpected connect error: {e}"; self.logger.exception(err_msg); self.ui_queue.put({"type": "connection_failed", "payload": f"Unexpected error: {e}"});
        finally:
             if client_socket and not self.peer_socket: client_socket.close()

    def send_data(self, data_dict): # ... (Same as simplified version) ...
        if not self.peer_socket: self.logger.error("send_data failed: No peer socket."); return False
        try: message = json.dumps(data_dict) + '\n'; encoded_message = message.encode('utf-8'); self.peer_socket.sendall(encoded_message); self.logger.debug(f"Sent {len(encoded_message)} bytes. Type: {data_dict.get('type', 'N/A')}"); return True
        except (OSError, BrokenPipeError, ConnectionAbortedError) as e: self.logger.warning(f"Send failed (connection likely lost): {e}"); return False
        except Exception as e: self.logger.exception("Unexpected error sending data"); self.add_message_to_history(f"Error sending data: {e}", 'error'); return False

    def start_receive_thread(self): # ... (Same as simplified version) ...
        if self.receive_thread and self.receive_thread.is_alive(): self.logger.warning("Receive thread already running."); return
        self.receive_thread = threading.Thread(target=self.receive_loop, name="ReceiveThread", daemon=True); self.logger.info("Starting receive thread."); self.receive_thread.start()

    def receive_loop(self): # ... (Same as simplified version) ...
        buffer = ""; peer_addr_info = f"({self.peer_address[0]}:{self.peer_address[1]})" if self.peer_address else "(Unknown Peer)"; self.logger.info(f"Receive loop started for peer: {peer_addr_info}")
        while self.is_running and self.peer_socket:
            try:
                data = self.peer_socket.recv(BUFFER_SIZE)
                if not data: self.logger.info("Peer closed connection (recv 0 bytes)."); self.handle_disconnect("Peer closed the connection."); break
                try: buffer += data.decode('utf-8')
                except UnicodeDecodeError: self.logger.error("Received non-UTF-8 data."); self.handle_disconnect("Received invalid data."); break
                while '\n' in buffer:
                    message_str, buffer = buffer.split('\n', 1)
                    if message_str:
                        self.logger.debug(f"Recv raw line: {message_str[:150]}...")
                        try: message_dict = json.loads(message_str); self.process_received_data(message_dict)
                        except json.JSONDecodeError: self.logger.error(f"Invalid JSON received: {message_str[:150]}..."); self.handle_disconnect("Received malformed JSON."); break
                        except Exception as e: self.logger.exception(f"Error processing dict type: {message_dict.get('type', 'N/A')}"); self.handle_disconnect(f"Internal processing error: {e}"); break
                    if not self.peer_socket or not self.is_running: break
                if not self.peer_socket or not self.is_running: break
            except ConnectionResetError: self.logger.warning("Connection reset by peer."); self.handle_disconnect("Connection reset by peer."); break
            except socket.timeout: self.logger.warning("Socket timeout in receive loop."); self.handle_disconnect("Socket timeout."); break
            except OSError as e:
                if self.is_running and self.state != STATE_DISCONNECTED: self.logger.error(f"Network error in receive loop: {e}"); self.handle_disconnect(f"Network error: {e}");
                else: self.logger.info(f"Receive loop OSError ignored (State={self.state}, Running={self.is_running}): {e}")
                break
            except Exception as e:
                if self.is_running: self.logger.exception("Unexpected error in receive loop"); self.ui_queue.put({"type":"error", "payload": f"Receive loop error: {e}"})
                break
        self.logger.info(f"Receive loop finished for peer: {peer_addr_info}")

    def handle_disconnect(self, reason=""): # ... (Same as simplified version) ...
        if self.state not in [STATE_DISCONNECTED, STATE_INITIAL, STATE_ERROR]:
            current_state = self.state; self.logger.warning(f"Disconnecting. Reason: {reason}"); self.state = STATE_DISCONNECTED; self.peer_is_ready = False; self.local_is_ready = False
            peer_sock = self.peer_socket; server_sock = self.server_socket; self.peer_socket = None; self.server_socket = None
            if peer_sock: self.logger.info("Closing peer socket.")
            try:
                peer_sock.shutdown(socket.SHUT_RDWR) 
            except OSError: 
                pass
            finally: 
                try:
                    peer_sock.close() 
                except OSError as e: 
                    self.logger.warning(f"Ignoring peer close error: {e}")
            if server_sock: 
                self.logger.info("Closing server socket.")
                try: server_sock.close() 
                except OSError as e: 
                    self.logger.warning(f"Ignoring server close error: {e}")
            if current_state != STATE_ERROR: self.ui_queue.put({"type": "connection_lost", "payload": f"{reason}"})
            else: self.ui_queue.put({"type": "set_state", "payload": STATE_DISCONNECTED})
        elif self.state in [STATE_DISCONNECTED, STATE_ERROR]: self.logger.info(f"handle_disconnect called in state {self.state}. Ensuring cleanup."); self.peer_socket = None; self.server_socket = None; self.peer_is_ready = False; self.local_is_ready = False


    # --- Key Exchange & Ratchet Methods ---

    def initiate_key_exchange(self):
        """Host starts key exchange: Sends Signed EdPub + X25519Pub + Nonce + Initial DHR Pub."""
        if not self.peer_socket: self.logger.error("Cannot initiate key exchange: Not connected."); return

        self.ui_queue.put({"type": "set_state", "payload": STATE_WAITING_FOR_KEYS})

        try:
            # Generate initial X25519 keys for the main DH exchange
            self.my_exchange_priv, self.my_exchange_pub = crypto_utils.generate_exchange_keys()
            # Generate initial Double Ratchet DH key pair
            self.dhr_self_priv, self.dhr_self_pub_obj = crypto_utils.generate_exchange_keys()
            dhr_self_pub_bytes = crypto_utils.serialize_public_key(self.dhr_self_pub_obj)

            self.key_exchange_nonce = os.urandom(crypto_utils.KEY_EXCHANGE_NONCE_SIZE)
            self.logger.info(f"Generated key exchange nonce (host): {self.key_exchange_nonce.hex()[:16]}...")
            self.logger.info(f"Generated initial DHR key pair (host). Pub: {dhr_self_pub_bytes.hex()[:16]}...")

            my_signing_pub_bytes = crypto_utils.serialize_public_key(self.my_signing_pub)
            my_exchange_pub_bytes = crypto_utils.serialize_public_key(self.my_exchange_pub)

            # Data to sign: Base Keys + Nonce + Initial DHR Public Key
            data_to_sign = my_signing_pub_bytes + my_exchange_pub_bytes + self.key_exchange_nonce + dhr_self_pub_bytes
            signature = crypto_utils.sign_data(self.my_signing_priv, data_to_sign)

            key_data = {
                "type": "key_exchange",
                "payload": {
                    "signing_key": crypto_utils.encode_base64(my_signing_pub_bytes),
                    "exchange_key": crypto_utils.encode_base64(my_exchange_pub_bytes),
                    "nonce": crypto_utils.encode_base64(self.key_exchange_nonce),
                    "dhr_pub": crypto_utils.encode_base64(dhr_self_pub_bytes), # Send initial DHR pub
                    "signature": crypto_utils.encode_base64(signature)
                }
            }
            self.add_message_to_history("Initiating secure key exchange...", 'system')
            self.logger.info("Sending initial key exchange message (host).")
            if not self.send_data(key_data): self.handle_disconnect("Failed to send initial keys.")

        except Exception as e:
            self.logger.exception("Error during key exchange initiation."); self.add_message_to_history(f"Error starting key exchange: {e}", 'error'); self.handle_disconnect(f"Key exchange init error: {e}")


    def process_key_exchange(self, payload):
        """Processes keys, verifies signature/nonce, handles roles, extracts initial DHR, performs SAS."""
        # Runs in ReceiveThread
        self.logger.info(f"Processing key exchange message (role: {self.connection_role})")
        self.provisional_shared_secret = None; self.current_sas_string = None
        peer_initial_dhr_pub_bytes = None

        try:
            # --- 1. Decode & Validate Payload ---
            # ... (Decoding logic remains the same) ...
            try:
                # ... (get fields from payload) ...
                peer_signing_key_b64 = payload["signing_key"]
                peer_exchange_key_b64 = payload["exchange_key"]
                peer_nonce_b64 = payload["nonce"]
                peer_dhr_pub_b64 = payload["dhr_pub"] # Expect initial DHR pub
                peer_signature_b64 = payload["signature"]
            except KeyError as e: raise ValueError(f"Missing field: {e}")
            # ... (decode base64) ...
            peer_signing_key_bytes = crypto_utils.decode_base64(peer_signing_key_b64); # ... etc ...
            peer_exchange_key_bytes = crypto_utils.decode_base64(peer_exchange_key_b64)
            peer_nonce = crypto_utils.decode_base64(peer_nonce_b64)
            peer_initial_dhr_pub_bytes = crypto_utils.decode_base64(peer_dhr_pub_b64)
            peer_signature = crypto_utils.decode_base64(peer_signature_b64)
            # ... (validation checks) ...
            if not all([...]): raise ValueError("Invalid Base64 encoding.")
            if len(peer_nonce) != crypto_utils.KEY_EXCHANGE_NONCE_SIZE: raise ValueError(f"Incorrect nonce size.")
            if len(peer_initial_dhr_pub_bytes) != crypto_utils.EXCHANGE_KEY_SIZE: raise ValueError("Incorrect DHR public key size.")


            self.peer_signing_pub_bytes = peer_signing_key_bytes
            self.peer_fingerprint_current = crypto_utils.get_fingerprint(self.peer_signing_pub_bytes)
            # ... (rest of fingerprint check, UI update) ...
            if not self.peer_fingerprint_current: raise ValueError("Failed to generate fingerprint.")
            self.logger.info(f"Received keys from peer FP: {self.peer_fingerprint_current}")
            self.ui_queue.put({"type": "set_state", "payload": self.state})

            # 2. Blocklist Check
            if self.peer_fingerprint_current in self.blocked_fingerprints: self.logger.warning(f"Blocked peer: {self.peer_fingerprint_current}"); self.add_message_to_history(f"Blocked peer {self.peer_fingerprint_current}.", 'error'); self.handle_disconnect("Blocked peer."); return

            # 3. Signature Verification
            peer_signing_pub = crypto_utils.deserialize_public_signing_key(peer_signing_key_bytes)
            if not peer_signing_pub: raise ValueError("Failed to deserialize peer signing key.")
            # Signed data now includes the initial DHR public key
            data_that_was_signed = peer_signing_key_bytes + peer_exchange_key_bytes + peer_nonce + peer_initial_dhr_pub_bytes
            if not crypto_utils.verify_signature(peer_signing_pub, peer_signature, data_that_was_signed): self.logger.critical("!!! SIGNATURE INVALID !!!"); self.add_message_to_history("!!! INVALID SIGNATURE! Disconnecting. !!!", 'error'); self.handle_disconnect("Invalid key signature."); return
            self.logger.info("Peer signature verified successfully.")

            # 4. Deserialize Peer Exchange Key
            self.peer_exchange_pub = crypto_utils.deserialize_public_exchange_key(peer_exchange_key_bytes)
            if not self.peer_exchange_pub: raise ValueError("Failed to deserialize peer exchange key.")

            # --- 5. Generate *Local* Initial Keys (if needed - mainly for Client) ---
            # Ensures self.my_exchange_priv/pub exist before DH calc or response sending
            # Host already generated these in initiate_key_exchange.
            if not hasattr(self, 'my_exchange_priv') or not self.my_exchange_priv:
                 self.logger.info("Generating initial exchange key pair (likely Client role).")
                 self.my_exchange_priv, self.my_exchange_pub = crypto_utils.generate_exchange_keys()
            # Also ensure initial DHR keys are generated locally before use
            if not hasattr(self, 'dhr_self_priv') or not self.dhr_self_priv:
                 self.logger.info("Generating initial DHR key pair (likely Client role).")
                 self.dhr_self_priv, self.dhr_self_pub_obj = crypto_utils.generate_exchange_keys()


            # --- 6. Nonce Check / Client Response ---
            if self.connection_role == 'client':
                # ... (Client stores nonce, prepares and sends response using self.my_exchange_*, self.dhr_self_*) ...
                self.key_exchange_nonce = peer_nonce
                # Keys should exist now from step 5
                dhr_self_pub_bytes = crypto_utils.serialize_public_key(self.dhr_self_pub_obj)
                my_signing_pub_bytes = crypto_utils.serialize_public_key(self.my_signing_pub)
                my_exchange_pub_bytes = crypto_utils.serialize_public_key(self.my_exchange_pub)
                data_to_sign = my_signing_pub_bytes + my_exchange_pub_bytes + self.key_exchange_nonce + dhr_self_pub_bytes
                signature = crypto_utils.sign_data(self.my_signing_priv, data_to_sign)
                key_data = { "type": "key_exchange", "payload": { "signing_key": crypto_utils.encode_base64(my_signing_pub_bytes), "exchange_key": crypto_utils.encode_base64(my_exchange_pub_bytes),"nonce": crypto_utils.encode_base64(self.key_exchange_nonce), "dhr_pub": crypto_utils.encode_base64(dhr_self_pub_bytes), "signature": crypto_utils.encode_base64(signature)}}
                self.add_message_to_history("Peer keys verified. Sending secure response...", 'system'); self.logger.info("Sending key exchange response (client).")
                if not self.send_data(key_data): self.logger.error("Failed send key response (client)."); self.handle_disconnect("Failed send key response."); return

            elif self.connection_role == 'host':
                # ... (Host verifies nonce) ...
                if not self.key_exchange_nonce or peer_nonce != self.key_exchange_nonce: self.logger.critical(f"!!! NONCE MISMATCH !!!"); self.add_message_to_history("!!! NONCE MISMATCH! Disconnecting. !!!", 'error'); self.handle_disconnect("Nonce mismatch."); return
                self.logger.info("Nonce verified successfully (host received client response).")
            else: raise ValueError(f"Unexpected role: {self.connection_role}")


            # --- 7. Calculate Provisional Secret ---
            # Both self.my_exchange_priv and self.peer_exchange_pub must exist here
            self.provisional_shared_secret = crypto_utils.perform_key_exchange(self.my_exchange_priv, self.peer_exchange_pub)
            if not self.provisional_shared_secret: raise ValueError("Initial DH exchange failed.")
            self.logger.info("Calculated provisional shared secret from initial exchange.")
            # DO NOT clear self.my_exchange_priv here

            # --- 8. Proceed to SAS Verification ---
            self.logger.info("Signature/Nonce OK. Proceeding to SAS verification.")
            my_initial_dhr_pub_bytes = crypto_utils.serialize_public_key(self.dhr_self_pub_obj)
            self.perform_sas_verification(my_initial_dhr_pub_bytes, peer_initial_dhr_pub_bytes)

        except (KeyError, TypeError, ValueError) as e: # ... (Error handling remains) ...
             self.logger.error(f"Error processing key exchange: {e}", exc_info=True); self.add_message_to_history(f"Error processing key data: {e}", 'error'); self.handle_disconnect("Invalid key data.")
        except Exception as e: # ... (Error handling remains) ...
             self.logger.exception("Unexpected error during key exchange"); self.add_message_to_history(f"Unexpected error during key exchange: {e}", 'error'); self.handle_disconnect("Key exchange failed.")

    def perform_sas_verification(self, my_dhr_pub_bytes, peer_dhr_pub_bytes):
        """Calculates and triggers the SAS verification dialog using initial DHR keys."""
        # Runs in ReceiveThread
        if not self.provisional_shared_secret or not self.peer_signing_pub_bytes or not self.key_exchange_nonce or not my_dhr_pub_bytes or not peer_dhr_pub_bytes:
            self.logger.error("Missing data required for SAS calculation."); self.handle_disconnect("Internal error preparing for SAS."); return
        try:
            my_signing_pub_bytes = crypto_utils.serialize_public_key(self.my_signing_pub)
            # Determine order based on role for consistent hashing
            if self.connection_role == 'host':
                host_sign_bytes, client_sign_bytes = my_signing_pub_bytes, self.peer_signing_pub_bytes
                host_exch_bytes, client_exch_bytes = my_dhr_pub_bytes, peer_dhr_pub_bytes # Use initial DHR pubs here
            else:
                host_sign_bytes, client_sign_bytes = self.peer_signing_pub_bytes, my_signing_pub_bytes
                host_exch_bytes, client_exch_bytes = peer_dhr_pub_bytes, my_dhr_pub_bytes

            sas_input_hash = crypto_utils.calculate_sas_input_hash(host_sign_bytes, client_sign_bytes, host_exch_bytes, client_exch_bytes, self.key_exchange_nonce, self.provisional_shared_secret)
            if not sas_input_hash: raise ValueError("SAS input hash calculation failed.")
            sas_bytes = crypto_utils.derive_sas_bytes(sas_input_hash)
            if not sas_bytes: raise ValueError("SAS byte derivation failed.")
            self.current_sas_string = crypto_utils.encode_sas_to_numbers(sas_bytes)
            if self.current_sas_string == "Error": raise ValueError("SAS string encoding failed.")

            # Store the peer's initial DHR pub now we've used it for SAS
            self.dhr_peer_pub = crypto_utils.deserialize_public_exchange_key(peer_dhr_pub_bytes)
            if not self.dhr_peer_pub: raise ValueError("Failed to deserialize peer initial DHR pub key.")
            self.logger.info(f"Stored peer initial DHR pub key. Bytes: {peer_dhr_pub_bytes.hex()[:16]}...")


            # Trigger SAS dialog via UI queue
            self.logger.info(f"Triggering SAS verification dialog. SAS: {self.current_sas_string}")
            self.ui_queue.put({"type": "show_sas_dialog", "payload": {"sas_string": self.current_sas_string}})

        except Exception as e:
            self.logger.exception("Error during SAS calculation/triggering."); self.add_message_to_history(f"Error preparing for SAS verification: {e}", 'error'); self.handle_disconnect("SAS preparation error.")


    def show_sas_verification_popup(self, sas_string): # ... (Same as before) ...
        self.logger.info(f"Displaying SAS verification dialog. SAS: {sas_string}"); self.update_ui_state(STATE_VERIFYING_KEYS)
        dialog = SASVerificationDialog(self.root, sas_string, self.handle_sas_result)
        try: self.root.wait_window(dialog)
        except tk.TclError: self.logger.warning("Main window destroyed during SAS dialog."); self.handle_disconnect("SAS Verification aborted.")


    def handle_sas_result(self, result): # ... (Simplified version - triggers auth completion on match) ...
        self.logger.info(f"SAS dialog result: '{result}'."); self.current_sas_string = None
        if result == 'match':
            self.add_message_to_history("SAS comparison successful.", 'system')
            self.logger.info("User confirmed SAS match.")

            # --- FIX: Promote secret FIRST ---
            if not self.provisional_shared_secret:
                self.logger.error("SAS matched but provisional secret is missing!")
                self.handle_disconnect("Internal SAS state error.")
                return
            self.shared_secret = self.provisional_shared_secret
            self.provisional_shared_secret = None # Clear provisional
            self.logger.info("Promoted provisional secret to final shared_secret.")
            # --- End Fix ---

            # --- FIX: Initialize ratchet using the FINAL secret ---
            if not self._initialize_ratchet(self.shared_secret, self.dhr_peer_pub):
                self.logger.error("Failed to initialize Double Ratchet state after SAS match.")
                self.handle_disconnect("Ratchet initialization failed.")
                return
            # --- End Fix ---

            self.logger.info("SAS matched & Ratchet Initialized. Triggering session authentication completion.")
            self.ui_queue.put({"type": "trigger_auth_completion"}) # Trigger final steps
        elif result == 'mismatch':
            self.add_message_to_history("!!! SAS MISMATCH! Disconnecting. Potential MitM! !!!", 'error'); self.logger.critical("!!! User reported SAS MISMATCH !!! Aborting."); self.provisional_shared_secret = None; self.handle_disconnect("SAS mismatch reported by user.")


    def _initialize_ratchet(self, root_key, peer_dhr_pub):
        """Initializes the Double Ratchet state after first key exchange and verification."""
        self.logger.info("Initializing Double Ratchet state...")
        try:
            # Initial Root Key is the secret from the main key exchange
            self.rk = root_key
            self.dhr_peer_pub = peer_dhr_pub # Already deserialized

            if not self.dhr_self_priv: # Should have been generated during exchange
                 self.logger.error("Cannot initialize ratchet: Own DHR private key missing.")
                 return False

            # Perform initial DH ratchet steps based on role
            if self.connection_role == 'host':
                # Host calculates first Sending Chain Key
                dh_out = crypto_utils.perform_key_exchange(self.dhr_self_priv, self.dhr_peer_pub)
                self.rk, self.cks = crypto_utils.dr_hkdf_rk(self.rk, dh_out)
                self.ckr = None # Receiving chain starts empty for host
                self.logger.info("Ratchet initialized (Host). RK and CKs derived.")
            elif self.connection_role == 'client':
                # Client calculates first Receiving Chain Key
                dh_out = crypto_utils.perform_key_exchange(self.dhr_self_priv, self.dhr_peer_pub)
                self.rk, self.ckr = crypto_utils.dr_hkdf_rk(self.rk, dh_out)
                self.cks = None # Sending chain starts empty for client
                self.logger.info("Ratchet initialized (Client). RK and CKr derived.")
            else:
                 self.logger.error(f"Cannot initialize ratchet in unknown role: {self.connection_role}")
                 return False

            if not self.rk or (self.connection_role == 'host' and not self.cks) or (self.connection_role == 'client' and not self.ckr):
                 self.logger.error("Failed to derive initial RK/CK during ratchet initialization.")
                 return False

            # Reset counters
            self.ns = 0; self.nr = 0; self.pnr = 0
            self.mkskipped.clear() # Clear skipped keys from any previous session
            self.logger.info("Ratchet counters and skipped keys reset.")
            return True

        except Exception as e:
            self.logger.exception("Error initializing Double Ratchet state.")
            return False

    def _dh_ratchet_step(self, peer_dh_pub_obj):
        """Performs a DH ratchet step when a new peer DHR public key is received."""
        self.logger.info("Performing DH Ratchet step...")
        try:
            self.pnr = self.ns # Store messages sent in current sending chain
            self.ns = 0        # Reset sending counter
            self.nr = 0        # Reset receiving counter

            # Calculate DH output with old RK and peer's new pub key
            dh_out_recv = crypto_utils.perform_key_exchange(self.dhr_self_priv, peer_dh_pub_obj)
            new_rk_recv, self.ckr = crypto_utils.dr_hkdf_rk(self.rk, dh_out_recv)
            self.rk = new_rk_recv # Update Root Key
            self.logger.info("Derived new RK and CKr from received peer key.")

            # Generate new DHR key pair for sending
            self.dhr_self_priv, self.dhr_self_pub_obj = crypto_utils.generate_exchange_keys()
            dhr_self_pub_bytes = crypto_utils.serialize_public_key(self.dhr_self_pub_obj)
            self.logger.info(f"Generated new DHR key pair for sending. Pub: {dhr_self_pub_bytes.hex()[:16]}...")

            # Calculate DH output with new RK and new DHR pair
            dh_out_send = crypto_utils.perform_key_exchange(self.dhr_self_priv, peer_dh_pub_obj)
            new_rk_send, self.cks = crypto_utils.dr_hkdf_rk(self.rk, dh_out_send)
            self.rk = new_rk_send # Update Root Key again
            self.logger.info("Derived new RK and CKs using new self key.")

            # Update stored peer public key
            self.dhr_peer_pub = peer_dh_pub_obj

            if not self.rk or not self.cks or not self.ckr:
                 self.logger.error("Failed to derive keys during DH ratchet step.")
                 self.handle_disconnect("Internal ratchet error.")
                 return False
            return True

        except Exception as e:
            self.logger.exception("Error during DH ratchet step.")
            self.handle_disconnect("Internal ratchet error.")
            return False

    def _try_skipped_message_keys(self, peer_dh_pub_bytes, n):
        """Checks stored skipped keys for a match."""
        key_tuple = (peer_dh_pub_bytes, n)
        if key_tuple in self.mkskipped:
            mk = self.mkskipped[key_tuple]
            self.logger.info(f"Found message key for skipped message (PeerPub: {peer_dh_pub_bytes.hex()[:8]}..., N: {n}) in cache.")
            del self.mkskipped[key_tuple] # Use key once
            return mk
        return None

    def _store_skipped_message_key(self, peer_dh_pub_bytes, n, mk):
        """Stores a derived message key for potential later use."""
        if len(self.mkskipped) >= crypto_utils.DR_MAX_SKIPPED_MESSAGES:
            # Remove the oldest entry if cache is full
            try:
                self.mkskipped.popitem(last=False) # FIFO removal
                self.logger.warning("Max skipped message keys reached, removing oldest.")
            except KeyError: pass # Ignore if empty somehow

        key_tuple = (peer_dh_pub_bytes, n)
        if key_tuple not in self.mkskipped:
             self.logger.info(f"Storing key for skipped message (PeerPub: {peer_dh_pub_bytes.hex()[:8]}..., N: {n}).")
             self.mkskipped[key_tuple] = mk
        else:
             self.logger.warning(f"Attempted to store duplicate skipped message key for N={n}.")

    def complete_session_authentication(self):
        """Final step after SAS success. Resets counters, sends ready. Runs in UI Thread."""
        self.logger.info("Completing session authentication after SAS.")

        allowed_states = [STATE_VERIFYING_KEYS, STATE_CHAT_READY]
        if self.state not in allowed_states: # ... (handle unexpected state) ...
            self.logger.warning(f"complete_session_auth called in unexpected state: {self.state}.")
            self.handle_disconnect(f"State error ({self.state}).")
            return

        # Check for FINAL shared secret (should be set by handle_sas_result)
        if not self.shared_secret:
            self.logger.error("Cannot complete authentication: Final shared secret missing! (This should not happen)")
            self.handle_disconnect("Internal state error (missing final secret).")
            return

        # Reset counters (ratchet already initialized)
        # self.send_counter = 0; self.receive_counter = 0 # Counters are ns, nr now
        self.provisional_shared_secret = None # Ensure cleared
        self.logger.info("DR Counters already reset during ratchet init.") # Updated log

        # Set local ready flag & update UI state
        self.local_is_ready = True
        self.ui_queue.put({"type": "set_state", "payload": STATE_CHAT_READY})
        self.add_message_to_history("Peer verified via SAS. Waiting for peer confirmation...", 'system')

        # Send the ready signal
        self.logger.info("Sending 'session_ready' signal to peer.")
        if not self.send_data({"type": "session_ready", "payload": None}): # ... (handle send fail) ...
            self.logger.error("Failed send 'session_ready'. Disconnecting.")
            self.handle_disconnect("Failed send ready signal.")
            return

        # Cleanup initial exchange keys and nonce
        self.my_exchange_priv = None
        self.peer_exchange_pub = None # No longer storing self.my_exchange_pub anyway
        self.key_exchange_nonce = None
        self.logger.info("Initial exchange keys and key exchange nonce cleared from memory.")

    def check_and_enable_chat(self): # ... (Checks local_is_ready AND peer_is_ready) ...
        if self.state == STATE_CHAT_READY and self.local_is_ready and self.peer_is_ready:
            self.logger.info("Both peers ready. Enabling chat input.")
            self.ui_queue.put({"type": "enable_chat_widgets"})
            self.ui_queue.put({"type": "update_status", "payload": {"text": "Status: Secure session active.", "color": COLOR_GREEN}})
            self.add_message_to_history("Peer confirmed ready. Chat enabled!", 'system')
        else:
            self.logger.debug(f"Chat not enabled yet. State={self.state}, LocalReady={self.local_is_ready}, PeerReady={self.peer_is_ready}")


    def process_received_data(self, data_dict): # ... (Handles session_ready correctly) ...
        msg_type = data_dict.get("type"); payload = data_dict.get("payload"); self.logger.debug(f"Processing data: Type='{msg_type}', State='{self.state}'")
        if not msg_type: self.logger.warning("Recv msg with no type."); return
        if msg_type == "key_exchange": # ... (Key exchange logic - unchanged from simplified version) ...
             if self.connection_role == 'client': allowed_states = [STATE_CONNECTING, STATE_WAITING_FOR_KEYS, STATE_VERIFYING_KEYS]
             elif self.connection_role == 'host': allowed_states = [STATE_WAITING_FOR_CONNECTION, STATE_WAITING_FOR_KEYS, STATE_VERIFYING_KEYS]
             else: allowed_states = []; self.logger.error(f"key_exchange with role: {self.connection_role}")
             if self.peer_socket and self.state in allowed_states: self.logger.info(f"Processing key_exchange in state {self.state} (Role: {self.connection_role})"); self.process_key_exchange(payload)
             else: self.logger.warning(f"Ignored key_exchange. State={self.state}, Role={self.connection_role}");
        elif msg_type == "chat_message": # --- Modified for Double Ratchet ---
             if self.local_is_ready and self.peer_is_ready and self.state == STATE_CHAT_READY and self.rk: # Check if ratchet is initialized
                 if isinstance(payload, dict) and "dh_pub" in payload and "n" in payload and "ct" in payload:
                     self.process_ratchet_message(payload["dh_pub"], payload["n"], payload["ct"])
                 else: self.logger.error(f"Invalid DR chat message format."); self.handle_disconnect("Malformed DR message.")
             else: self.logger.warning(f"Ignored chat_message. State={self.state}, LocalReady={self.local_is_ready}, PeerReady={self.peer_is_ready}, RK exists={self.rk is not None}")
        elif msg_type == "session_ready": # ... (Same as previous, triggers check_enable_chat) ...
             if self.state in [STATE_CHAT_READY, STATE_VERIFYING_KEYS]:
                 if not self.peer_is_ready: self.logger.info("Received 'session_ready' from peer."); self.peer_is_ready = True; self.ui_queue.put({"type": "check_enable_chat_trigger"})
             else: self.logger.warning(f"Ignored 'session_ready' in state {self.state}.")
        else: self.logger.warning(f"Received unknown message type: '{msg_type}'.")


    def send_message_event(self, event=None):
        """Handles sending a chat message using the Double Ratchet."""
        message = self.message_entry.get().strip()
        if not message: return

        # Check core conditions first
        if not (self.state == STATE_CHAT_READY and self.local_is_ready and self.peer_is_ready):
            self.add_message_to_history("Cannot send: Session not fully active.", 'system'); return
        if not self.dhr_self_priv or not self.dhr_peer_pub: # Check necessary keys exist
            self.logger.error("Cannot send: Missing own/peer DHR keys for ratchet.")
            self.add_message_to_history("Error: Ratchet keys missing.", 'error'); return

        try:
            # --- FIX: Initialize sending chain if it's None ---
            if self.cks is None:
                self.logger.info("Sending chain key is None. Performing initial sending DH step.")
                # Perform DH calculation using current self.rk and peer's DHR pub
                dh_out_send = crypto_utils.perform_key_exchange(self.dhr_self_priv, self.dhr_peer_pub)
                # Update RK and initialize CKs
                new_rk, self.cks = crypto_utils.dr_hkdf_rk(self.rk, dh_out_send)
                if not new_rk or not self.cks:
                     self.logger.error("Failed to initialize sending chain.")
                     self.add_message_to_history("Error: Failed to setup sending keys.", 'error'); return
                self.rk = new_rk # Update root key
                self.logger.info("Initialized Sending Chain Key (CKs).")
            # --- End Fix ---


            # 1. Derive keys from Sending Chain
            mk, next_cks = crypto_utils.dr_kdf_ck(self.cks)
            if not mk or not next_cks: self.logger.error("Failed derive sending MK/CK."); self.add_message_to_history("Error: Key derivation failed.", 'error'); return
            self.cks = next_cks # Update sending chain key

            # 2. Package Header (DHR pub, message number)
            # Send the *current* DHR public key associated with this sending chain
            dhr_pub_obj_to_send = self.dhr_self_pub_obj
            dhr_pub_bytes = crypto_utils.serialize_public_key(dhr_pub_obj_to_send)
            header_data = dhr_pub_bytes + self.ns.to_bytes(4, 'big')

            # 3. Encrypt message
            nonce_ciphertext = crypto_utils.dr_encrypt(mk, message, header_data)
            if nonce_ciphertext is None: self.logger.error("Encryption failed."); self.add_message_to_history("Error: Encryption failed.", 'error'); return

            # 4. Construct payload
            payload = { "dh_pub": crypto_utils.encode_base64(dhr_pub_bytes), "n": self.ns, "ct": crypto_utils.encode_base64(nonce_ciphertext) }
            message_data = {"type": "chat_message", "payload": payload}

            # 5. Send data
            self.logger.info(f"Sending message Ns={self.ns} with DHR Pub: {dhr_pub_bytes.hex()[:16]}...")
            if self.send_data(message_data):
                self.message_entry.delete(0, tk.END)
                self.add_message_to_history(f"You: {message}", 'self')
                self.ns += 1 # Increment message counter AFTER successful send
            else:
                self.add_message_to_history("(Message not sent - connection issue?)", "error")

        except Exception as e: self.logger.exception("Error sending DR message"); self.add_message_to_history(f"Error sending message: {e}", 'error')

    def process_ratchet_message(self, peer_dh_pub_b64, n_peer, ct_b64):
        """Processes a received chat message using the Double Ratchet logic."""
        # Runs in ReceiveThread
        self.logger.info(f"Processing received DR message. Peer N={n_peer}, Current Nr={self.nr}")
        try:
            peer_dh_pub_bytes = crypto_utils.decode_base64(peer_dh_pub_b64)
            nonce_ciphertext = crypto_utils.decode_base64(ct_b64)
            if not peer_dh_pub_bytes or not nonce_ciphertext: raise ValueError("Invalid base64 in DR message payload")

            # Check cache for skipped message keys first
            mk = self._try_skipped_message_keys(peer_dh_pub_bytes, n_peer)
            if mk:
                self.logger.info("Found key in cache for skipped message.")
            else:
                # Key not cached
                current_peer_dhr_pub_bytes = crypto_utils.serialize_public_key(self.dhr_peer_pub) if self.dhr_peer_pub else None
                perform_dh_step = False

                # --- FIX: Check if CKr needs initialization OR if peer key changed ---
                if peer_dh_pub_bytes != current_peer_dhr_pub_bytes:
                    self.logger.info("New peer DHR public key received. Will perform DH ratchet step.")
                    # Store keys derived from the old CKr before performing step
                    self._store_skipped_keys_for_chain(current_peer_dhr_pub_bytes)
                    perform_dh_step = True
                elif self.ckr is None:
                    # This is likely the Host receiving the Client's *first* message.
                    # We need to initialize CKr even though the DHR key is the same initial one.
                    self.logger.info("Receiving chain key (CKr) is None. Will perform initial DH ratchet step.")
                    perform_dh_step = True
                # --- End Fix ---

                if perform_dh_step:
                    # Perform the DH ratchet step
                    peer_dh_pub_obj = crypto_utils.deserialize_public_exchange_key(peer_dh_pub_bytes)
                    if not peer_dh_pub_obj or not self._dh_ratchet_step(peer_dh_pub_obj):
                        return # Error handled inside _dh_ratchet_step
                    # After step, check cache again for the *new* CKr
                    # Use the *new* peer_dh_pub_bytes (which is current_peer_dhr_pub_bytes now)
                    mk = self._try_skipped_message_keys(peer_dh_pub_bytes, n_peer)


                # If key still not found (either same peer key or not in cache after ratchet step)
                if not mk:
                    # --- FIX: Check CKr *after* potential DH step ---
                    if not self.ckr:
                        self.logger.error("Cannot process message: Receiving chain key (CKr) is still not initialized after potential DH step.")
                        self.handle_disconnect("Internal ratchet state error (no CKr).")
                        return
                    # --- End Fix ---

                    if n_peer < self.nr:
                        self.logger.warning(f"Received old/duplicate message (Peer N={n_peer}, Current Nr={self.nr}). Ignoring.")
                        return

                    # Advance receiving chain to find the key, storing skipped keys
                    self.logger.debug(f"Advancing receive chain from Nr={self.nr} to Npeer={n_peer}...")
                    while self.nr < n_peer:
                        skipped_mk, next_ckr = crypto_utils.dr_kdf_ck(self.ckr)
                        if not skipped_mk or not next_ckr: self.logger.error("Failed to derive skipped MK/CKr."); self.handle_disconnect("Ratchet derivation failed."); return
                        self._store_skipped_message_key(peer_dh_pub_bytes, self.nr, skipped_mk)
                        self.ckr = next_ckr
                        self.nr += 1
                        if self.nr > n_peer + crypto_utils.DR_MAX_SKIPPED_MESSAGES: # Safety break
                             self.logger.error("Advanced ratchet too far searching for key."); self.handle_disconnect("Ratchet sync error."); return

                    # Derive the final message key and update CKr
                    final_mk, next_ckr = crypto_utils.dr_kdf_ck(self.ckr)
                    if not final_mk or not next_ckr: self.logger.error("Failed to derive final MK/CKr."); self.handle_disconnect("Ratchet derivation failed."); return
                    self.ckr = next_ckr
                    self.nr += 1 # Increment Nr for the next expected message
                    mk = final_mk # This is the key we need

            # 4. Decrypt Message (remains the same)
            # 4. Decrypt Message
            if not mk:
                # Should not happen if logic above is correct
                self.logger.error("Message key is unexpectedly None before decryption.")
                self.handle_disconnect("Internal key derivation error.")
                return
            header_data = peer_dh_pub_bytes + n_peer.to_bytes(4, 'big')
            plaintext = crypto_utils.dr_decrypt(mk, nonce_ciphertext, header_data)
            if plaintext is not None: # ... (handle success) ...
                self.logger.info(f"Successfully decrypted message N={n_peer}.")
                self.ui_queue.put({"type": "add_message", "payload": {"message": f"Peer: {plaintext}", "tag": "peer"}})
            else:
                # Decryption failed (warning logged by dr_decrypt)
                self.add_message_to_history(f"*** Failed to decrypt message (N={n_peer}). Corrupted or invalid. ***", 'error')
                # Consider disconnecting on decryption failures?

        # ... (Exception handling remains the same) ...
        except ValueError as e: self.logger.error(f"ValueError processing DR message: {e}"); self.add_message_to_history(f"*** Error processing message: {e} ***", 'error'); self.handle_disconnect(f"Invalid DR message format: {e}")
        except Exception as e: self.logger.exception("Unexpected error processing ratchet message"); self.add_message_to_history("*** Error processing message! ***", 'error'); self.handle_disconnect("Error processing message.")

    def _store_skipped_keys_for_chain(self, peer_dh_pub_bytes):
         """Derives and stores keys for the current receiving chain before a DH step."""
         if not self.ckr or not peer_dh_pub_bytes:
              self.logger.warning("Cannot store skipped keys: CKr or Peer Pub missing.")
              return
         self.logger.info(f"Storing any remaining keys for chain Nr={self.nr} before ratchet step...")
         # No explicit limit here, relies on DR_MAX_SKIPPED_MESSAGES during derivation
         # In theory, nr shouldn't be excessively large before a DH step occurs.
         temp_ck = self.ckr
         temp_nr = self.nr
         # Iterate cautiously - maybe limit this loop?
         max_store_ahead = 10 # Limit how many keys we proactively store
         count = 0
         while count < max_store_ahead:
              mk, next_ck = crypto_utils.dr_kdf_ck(temp_ck)
              if not mk or not next_ck:
                   self.logger.error(f"Failed to derive key while storing skipped keys at Nr={temp_nr}.")
                   break # Stop storing if derivation fails
              self._store_skipped_message_key(peer_dh_pub_bytes, temp_nr, mk)
              temp_ck = next_ck
              temp_nr += 1
              count += 1


    def on_closing(self):
        """Handles window close event ('X' button)."""
        self.logger.info("Close button clicked. Initiating shutdown sequence.")
        # Use askyesno for confirmation
        if messagebox.askyesno("Quit", "Are you sure you want to quit? This will close the connection.", parent=self.root):
            self.is_running = False # Signal threads to stop their loops

            # --- FIX: Handle peer socket closing more safely ---
            sock_to_close = None
            if self.peer_socket:
                self.logger.info("Attempting to close peer socket gracefully.")
                sock_to_close = self.peer_socket # Copy socket object to local var
                self.peer_socket = None # Set instance var to None immediately to signal closure intent

                try:
                    # Operate on the local copy
                    sock_to_close.shutdown(socket.SHUT_WR)
                except OSError as e:
                    # Ignore common errors indicating socket is already closed or not connected
                    if e.errno not in (107, 9, 57, 32): # ENOTCONN, EBADF, EPIPE etc.
                         self.logger.warning(f"Ignoring minor error during peer socket shutdown: {e} (errno={e.errno})")
                    else: # Log other errors potentially
                         self.logger.warning(f"Error during peer socket shutdown: {e} (errno={e.errno})")
                except Exception as e: # Catch other potential exceptions like AttributeError if somehow None slipped through
                    self.logger.error(f"Unexpected error during peer socket shutdown: {e}")
                finally:
                    try:
                        # Close the local copy
                        sock_to_close.close()
                        self.logger.info("Peer socket closed.")
                    except OSError as e:
                        self.logger.warning(f"Ignoring error closing peer socket copy: {e}")
                    except Exception as e:
                         self.logger.error(f"Unexpected error closing peer socket copy: {e}")
            # Ensure instance variable is None even if the initial check failed
            self.peer_socket = None
            # --- End Fix ---


            # Close server socket (if exists) using a similar safe pattern
            server_sock_to_close = self.server_socket
            if server_sock_to_close:
                self.logger.info("Closing server socket.")
                self.server_socket = None # Set instance var to None
                try:
                    server_sock_to_close.close()
                except OSError as e:
                    self.logger.warning(f"Ignoring error closing server socket: {e}")
            self.server_socket = None


            # Give daemon threads a moment to potentially finish based on is_running flag
            time.sleep(0.1) # Short delay

            # Destroy the Tkinter window
            self.logger.info("Destroying Tkinter root window.")
            try:
                self.root.destroy()
            except tk.TclError:
                self.logger.warning("Root window already destroyed during shutdown.")
            self.logger.info(f"--- {APP_NAME} Application Closed ---")
        else:
            self.logger.info("Quit cancelled by user.")


# --- Main Execution --- (Same as simplified version)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s')
    root = tk.Tk(); app_instance = None
    try:
        if os.name == 'nt':
            try: from ctypes import windll; windll.shcore.SetProcessDpiAwareness(1)
            except Exception: 
                try: windll.user32.SetProcessDPIAware() 
                except Exception: logging.warning("Could not set DPI awareness.")
        app_instance = P2PChatApp(root)
        if app_instance and app_instance.is_running: root.mainloop()
        elif not app_instance: logging.critical("App instance failed create.")
    except Exception as e:
        logging.critical("Fatal error during startup/main loop.", exc_info=True)
        try: parent_win = root if root.winfo_exists() else None; messagebox.showerror("Fatal Error", f"Critical error:\n{e}\n\nCheck {LOG_FILE}.", parent=parent_win)
        except Exception as me: print(f"FATAL ERROR: {e}. MsgBoxErr: {me}. Check {LOG_FILE}.")
        finally:
             if root and root.winfo_exists(): root.destroy()
    logging.info(f"--- {APP_NAME} Main execution finished ---")