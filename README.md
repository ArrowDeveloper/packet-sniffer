# Packet Sniffer

This repository contains a low level packet sniffer built using socket and struct in Python and C. This is currently made for only Linux OS.

### Features

## For Python

* Easy to use
* Made for beginners
* Auto detects network interface

## For C

* Contains hexdump function for viewing raw bytes in hex form
* Helps learn basic C networking
* Helps learn basic packet decoding

### Usage

# For Python:

```bash
sudo python3 packetsniffer.py
```

# For C:

```bash
gcc packetsniffer.c utilities.c -o packetsniffer
sudo ./packetsniffer
```

---
# Disclaimer

This tool is intended **for educational purposes only**.
Only scan systems that you own or have explicit permission to test.

---