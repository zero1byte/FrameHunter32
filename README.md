# FrameHunter32

ESP32-based Wi-Fi analysis and packet sniffing tool developed using the Espressif ESP-IDF framework.
Designed for wireless monitoring, frame analysis, access point discovery, and WPA/WPA2 handshake capture.

---

## Features

* Wi-Fi packet sniffing using promiscuous mode
* WPA/WPA2 4-way handshake capture
* Access Point (AP) scanning
* Beacon frame analysis
* Probe request and response monitoring
* Raw 802.11 frame parsing
* MAC address extraction
* Real-time packet logging via serial console
* Lightweight embedded implementation on ESP32
* Built with native ESP-IDF framework in C

---

## Technologies Used

* ESP32
* C Programming Language
* Espressif ESP-IDF
* IEEE 802.11 Wireless Protocols

---

## Project Structure

```text
.
├── main/
│   ├── main.c
│   ├── sniff.c
│   ├── parser.c
│   └── scanner.c
├── CMakeLists.txt
├── sdkconfig
└── README.md
```

---

## Requirements

### Hardware

* ESP32 Development Board
* USB Cable

### Software

* ESP-IDF Framework
* Python 3
* CMake
* Ninja Build System

---

## Setup

Clone the repository:

```bash
git clone https://github.com/yourusername/ESPectre.git
cd ESPectre
```

Export ESP-IDF environment:

```bash
source $HOME/esp/esp-idf/export.sh
```

Build the project:

```bash
idf.py build
```

Flash to ESP32:

```bash
idf.py flash
```

Open serial monitor:

```bash
idf.py monitor
```

---

## Usage

The firmware can:

* Scan nearby Wi-Fi access points
* Capture raw IEEE 802.11 frames
* Detect WPA/WPA2 authentication traffic
* Capture 4-way handshakes for analysis
* Display frame information over serial output

---

## Future Plans

* Channel hopping support
* PCAP file export
* Deauthentication detection
* Client tracking
* EAPOL packet filtering
* Web dashboard
* SD card logging
* OLED/TFT display support
* Remote monitoring interface

---

## Disclaimer

This project is intended strictly for educational purposes, wireless protocol research, and authorized security testing only.
Do not use this project on networks without proper authorization.

---

## License

MIT License

---

## Author

Developed using ESP-IDF and ESP32 for wireless security research and embedded networking experimentation.
