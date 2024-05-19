# Packet Sniffer GUI

This project provides a graphical user interface (GUI) for a packet sniffer application using Python's `tkinter` library and `scapy`. The application allows users to sniff network packets on selected interfaces with optional protocol filtering.

## Features

- **Graphical User Interface**: Built with `tkinter`, making it user-friendly to interact with the packet sniffing functionalities.
- **Network Interface Selection**: Users can select which network interface to sniff on.
- **Packet Count Limit**: Option to specify the number of packets to sniff.
- **Protocol Filtering**: Users can choose to filter the sniffed packets by a specific protocol.
- **Real-time Packet Display**: Sniffed packets are displayed in real-time within the GUI.

## Requirements

- Python 3.x
- `tkinter` library
- `scapy` library

## Setup and Installation

1. Ensure Python 3.x is installed on your system.
2. Install the required Python libraries:
   ```bash
   pip install scapy
   ```
3. Clone the repository or download the source code.

## Usage

1. Run the `GUI.py` script:
   ```bash
   python GUI.py
   ```
2. Use the GUI to start sniffing by selecting the interface and specifying other parameters like packet count and protocol filtering.

## Code Structure

- `SniffApp`: Main class handling the GUI and integration with the `scapy` sniffing functionalities.
- `start_sniffing`: Method to initiate the sniffing process based on user inputs.
- `display_interfaces`: Method to display available network interfaces.
- `PcktInfo`: Callback method to handle and display each sniffed packet.

## Contributing

Contributions to the project are welcome! Please fork the repository and submit a pull request with your features or fixes.

## License

This project is open-sourced under the MIT License. See the LICENSE file for more details.