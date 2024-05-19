import tkinter as tk
from tkinter import simpledialog, scrolledtext
from scapy.all import sniff
import subprocess


class SniffApp:
    def __init__(self, master):
        self.master = master
        master.title("Packet Sniffer")
        master.geometry("760x540")  # Set the resolution of the window

        self.label = tk.Label(master, text="Packet Sniffer Interface")
        self.label.pack()

        self.sniff_button = tk.Button(
            master, text="Start Sniffing", command=self.start_sniffing)
        self.sniff_button.pack()

        self.exit_button = tk.Button(master, text="Exit", command=master.quit)
        self.exit_button.pack()

        # Text widget to display the sniffing output
        self.output_text = scrolledtext.ScrolledText(master, height=30)
        self.output_text.pack(pady=10)

    def display_interfaces(self):
        try:
            result = subprocess.run(
                ['ipconfig'], capture_output=True, text=True, check=True)
            self.output_text.insert(tk.END, result.stdout + '\n')
        except subprocess.CalledProcessError as e:
            self.output_text.insert(tk.END, f"Error: {e.stderr}\n")

    def PcktInfo(self, packet):
        # Display packet info in the Text widget
        self.output_text.insert(tk.END, str(packet) + '\n')

    def start_sniffing(self):
        self.display_interfaces()
        interface = simpledialog.askstring(
            "Input", "Select the interface you want to sniff on:")
        limit = simpledialog.askinteger(
            "Input", "Enter the number of packets to sniff (0 for unlimited):")
        answer = simpledialog.askstring(
            "Input", "Do you wish to filter by a specific protocol? (Y/N)")

        if limit == 0:
            if answer.lower() == "y":
                protocol = simpledialog.askstring(
                    "Input", "Specify the protocol:")
                sniff(filter=protocol, iface=interface, prn=self.PcktInfo)
            else:
                sniff(iface=interface, prn=self.PcktInfo)
        else:
            if answer.lower() == "y":
                protocol = simpledialog.askstring(
                    "Input", "Specify the protocol:")
                sniff(filter=protocol, iface=interface,
                      prn=self.PcktInfo, count=limit)
            else:
                sniff(iface=interface, prn=self.PcktInfo, count=limit)


root = tk.Tk()
app = SniffApp(root)
root.mainloop()
