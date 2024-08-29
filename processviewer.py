import psutil
import tkinter as tk
from tkinter import scrolledtext, Menu, simpledialog, messagebox, ttk, StringVar, Toplevel, Button, Label, Entry
import threading
import os

class ProcessViewerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Process Viewer")
        self.geometry("800x600")
        self.scanned_memory = {}
        self.show_base_addresses = tk.BooleanVar(value=True)

        self.check_superuser()
        self.create_widgets()
        self.update_process_list()

    def check_superuser(self):
        if not self.is_superuser():
            messagebox.showwarning("Superuser Required",
                                   "This program requires superuser privileges. "
                                   "Please run as root or use sudo.")

    def is_superuser(self):
        return os.geteuid() == 0

    def create_widgets(self):
        self.create_menu()

        self.refresh_button = tk.Button(self, text="Refresh", command=self.update_process_list)
        self.refresh_button.pack(pady=10)

        self.search_var = StringVar()
        self.search_entry = tk.Entry(self, textvariable=self.search_var)
        self.search_entry.pack(pady=5)
        self.search_entry.bind("<Return>", lambda event: self.search_process())

        self.tree = ttk.Treeview(self, columns=("PID", "Name", "Base Address"), show='headings')
        self.tree.heading("PID", text="PID")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Base Address", text="Base Address")
        self.tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.context_menu = Menu(self, tearoff=0)
        self.context_menu.add_command(label="Scan Memory", command=self.start_memory_scan)
        self.context_menu.add_command(label="View Scanned Strings", command=self.view_scanned_strings)

        self.tree.bind("<Button-3>", self.show_context_menu)

        self.progress_label = tk.Label(self, text="")
        self.progress_label.pack(pady=5)

    def create_menu(self):
        menubar = tk.Menu(self)
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_checkbutton(label="Show Base Addresses", onvalue=True, offvalue=False,
                                      variable=self.show_base_addresses, command=self.update_process_list)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        self.config(menu=menubar)

    def update_process_list(self):
        self.tree.delete(*self.tree.get_children())
        self.processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.info['pid']
            name = proc.info['name']
            base_addresses = self.get_base_addresses(pid) if self.show_base_addresses.get() else ['N/A']
            base_addresses_str = ', '.join(base_addresses) if base_addresses else 'N/A'
            self.processes.append((pid, name, base_addresses))
            self.tree.insert("", "end", values=(pid, name, base_addresses_str))

    def get_base_addresses(self, pid):
        try:
            with open(f"/proc/{pid}/maps") as f:
                lines = f.readlines()
            addresses = []
            for line in lines:
                parts = line.split()
                if parts:
                    addr_range = parts[0]
                    start_addr = addr_range.split('-')[0]
                    if 'r-xp' in parts or 'rw-p' in parts:
                        addresses.append(start_addr)
            return addresses
        except FileNotFoundError:
            return []
        except Exception as e:
            return [f"Error: {e}"]

    def show_context_menu(self, event):
        try:
            item = self.tree.identify_row(event.y)
            if item:
                self.selected_process = self.tree.item(item, 'values')
                self.context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open context menu: {e}")

    def start_memory_scan(self):
        if hasattr(self, 'selected_process'):
            pid = self.selected_process[0]
            scan_thread = threading.Thread(target=self.scan_memory, args=(pid,))
            scan_thread.start()
        else:
            messagebox.showwarning("No Selection", "No process selected.")

    def scan_memory(self, pid):
        self.scanned_memory[pid] = []
        maps = self.get_memory_maps(pid)
        total_strings = 0  # Initialize counter for the number of strings found
        total_blocks = len(maps)  # Total number of memory blocks to scan
        scanned_blocks = 0  # Counter for scanned memory blocks

        self.progress_label.config(text=f"Strings found: {total_strings} / Scanning block: {scanned_blocks}/{total_blocks}")

        try:
            with open(f"/proc/{pid}/mem", "rb") as mem_file:
                for start_addr, end_addr in maps:
                    try:
                        mem_file.seek(start_addr)
                        memory_data = mem_file.read(end_addr - start_addr)
                        strings_found = self.extract_strings_from_memory(pid, start_addr, memory_data)
                        total_strings += strings_found  # Update total number of strings found
                        scanned_blocks += 1  # Update the number of scanned blocks
                        self.progress_label.config(text=f"Strings found: {total_strings} / Scanning block: {scanned_blocks}/{total_blocks}")
                    except Exception as e:
                        continue
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan memory: {e}")
        self.progress_label.config(text=f"Memory scan completed. Total strings found: {total_strings}")

    def extract_strings_from_memory(self, pid, start_addr, memory_data):
        current_string = ""
        strings_found = 0  # Counter for strings found in this memory block
        for i, byte in enumerate(memory_data):
            if 32 <= byte <= 126:  # ASCII printable characters
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:  # Save strings of length 4 or more
                    self.scanned_memory[pid].append((hex(start_addr + i - len(current_string)), current_string))
                    strings_found += 1  # Increment counter when a string is found
                current_string = ""
        if len(current_string) >= 4:
            self.scanned_memory[pid].append((hex(start_addr + len(memory_data) - len(current_string)), current_string))
            strings_found += 1  # Increment counter when a string is found
        return strings_found  # Return the number of strings found in this block

    def get_memory_maps(self, pid):
        maps = []
        try:
            with open(f"/proc/{pid}/maps") as f:
                for line in f:
                    parts = line.split()
                    if parts:
                        addr_range = parts[0]
                        start_addr, end_addr = map(lambda x: int(x, 16), addr_range.split('-'))
                        maps.append((start_addr, end_addr))
        except FileNotFoundError:
            pass
        return maps

    def view_scanned_strings(self):
        if hasattr(self, 'selected_process'):
            pid = self.selected_process[0]
            if pid in self.scanned_memory:
                self.show_scanned_strings_window(pid)
            else:
                messagebox.showwarning("No Memory Scan", "Please scan the memory first.")
        else:
            messagebox.showwarning("No Selection", "No process selected.")
    def show_scanned_strings_window(self, pid):
        result_window = Toplevel(self)
        result_window.title(f"Scanned Strings - PID: {pid}")
        result_window.geometry("800x600")

        progress_label = Label(result_window, text="Loading scanned strings...")
        progress_label.pack(pady=5)

        scrolled_text = scrolledtext.ScrolledText(result_window)
        scrolled_text.pack(fill=tk.BOTH, expand=True)

        filter_button = Button(result_window, text="Filter", command=lambda: self.open_filter_window(pid))
        filter_button.pack(side=tk.LEFT, padx=10, pady=10)

        load_thread = threading.Thread(target=self.load_scanned_strings, args=(pid, scrolled_text, progress_label))
        load_thread.start()

    def load_scanned_strings(self, pid, scrolled_text, progress_label):
        total_strings = len(self.scanned_memory[pid])
        loaded_strings = 0

        for addr, string in self.scanned_memory[pid]:
            scrolled_text.insert(tk.END, f"Address: {addr} - String: {string}\n")
            loaded_strings += 1
            progress_label.config(text=f"Loaded {loaded_strings}/{total_strings} strings")

        progress_label.config(text="All strings loaded.")
        scrolled_text.configure(state='disabled')

    def open_filter_window(self, pid):
        filter_window = Toplevel(self)
        filter_window.title("Filter Strings")
        filter_window.geometry("300x100")

        Label(filter_window, text="Enter filter text:").pack(pady=5)
        filter_entry = Entry(filter_window)
        filter_entry.pack(pady=5)

        filter_button = Button(filter_window, text="Apply Filter", command=lambda: self.apply_filter(pid, filter_entry.get(), filter_window))
        filter_button.pack(pady=5)

    def apply_filter(self, pid, filter_text, filter_window):
        if pid in self.scanned_memory:
            filtered_results = [(addr, string) for addr, string in self.scanned_memory[pid] if filter_text in string]
            self.show_filtered_results(filtered_results)
        filter_window.destroy()

    def show_filtered_results(self, filtered_results):
        result_window = Toplevel(self)
        result_window.title("Filtered Results")
        result_window.geometry("800x600")

        scrolled_text = scrolledtext.ScrolledText(result_window)
        scrolled_text.pack(fill=tk.BOTH, expand=True)

        if filtered_results:
            for addr, string in filtered_results:
                scrolled_text.insert(tk.END, f"Address: {addr} - String: {string}\n")
        else:
            scrolled_text.insert(tk.END, "No matching strings found.")

        scrolled_text.configure(state='disabled')

if __name__ == "__main__":
    app = ProcessViewerApp()
    app.mainloop()