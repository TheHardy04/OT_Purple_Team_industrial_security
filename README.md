# OT Purple Team Industrial Security

This project provides a practical environment for exploring industrial and
operational technology (OT) security with [O.I.D.A.](https://getoida.dev),
the OT/ICS Dynamic Assessment framework.

## Concepts for beginners

### Operational Technology

**Operational Technology (OT)** includes systems that monitor or control
physical processes, such as pumps, ventilation, power equipment, and
manufacturing lines. OT commonly uses:

- **SCADA**: supervisory control and data acquisition for monitoring processes.
- **HMI**: a human-machine interface, usually an operator screen.
- **PLC**: a programmable logic controller that executes control logic and
  communicates with sensors and actuators.

A SCADA system or HMI may act as a master, sending requests to a PLC or field
device acting as a slave. OT environments prioritize safety and availability,
so testing must be authorized and carefully controlled.

### Modbus/TCP

**Modbus/TCP** carries Modbus requests and responses between masters and field
devices over a TCP connection, normally on **TCP/502**. It has no built-in
authentication or encryption, so network segmentation and access control are
important.

A Modbus/TCP frame has two parts:

- **MBAP Header**: the 7-byte Modbus Application Protocol header. It contains
  the Transaction Identifier, Protocol Identifier, Length, and Unit Identifier.
- **PDU**: the Protocol Data Unit. It contains a Function Code and operation
  data.

A **Function Code (FC)** specifies the operation, such as `FC 03 / 0x03`
(Read Holding Registers). Public Function Codes are standardized operations.
Codes `65–127 / 0x41–0x7F` are reserved or vendor/user-defined and may be
unsupported. An exception response sets the `0x80` bit in the echoed FC and
returns an Exception Code; for example, `0xC1` is FC `0x41` with the exception
bit set, and code `0x01` means Illegal Function.

### Suricata

[Suricata](https://suricata.io/) is a network Intrusion Detection System (IDS).
It inspects packet payloads and generates alerts when traffic matches signature
rules. A Suricata rule generally has this structure:

```text
action protocol src_ip src_port -> dst_ip dst_port (rule options)
```

For example, `alert tcp any any -> any 502 (...)` means: alert on TCP traffic
sent from any source to destination port 502.

The rule keywords used in this repository mean:

- `flow`: limits inspection to a traffic direction and connection state.
- `content`: searches payload bytes.
- `offset`: sets the byte position at which to begin an inspection.
- `depth`: limits a search to a fixed payload length.
- `byte_test`: compares or masks a numeric byte.
- `threshold`: controls repeated alerts over a count and time window.
- `classtype`: assigns an alert category.
- `sid`: provides the signature's unique ID.
- `rev`: identifies the signature revision.

## Setup

Create and activate a Python virtual environment, then install the project dependencies:

```shell
pip install -r requirements.txt
```

## Exploring targets

With the virtual environment activated, display the available commands and options:

```shell
oida -help
```

The command displays:

```txt
     ██████╗ ██╗██████╗  █████╗
    ██╔═══██╗██║██╔══██╗██╔══██╗
    ██║   ██║██║██║  ██║███████║
    ██║   ██║██║██║  ██║██╔══██║
    ╚██████╔╝██║██████╔╝██║  ██║
     ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝  v1.0.6

    Scan. Fuzz. Assess. Responsibly in OT.
    https://getoida.dev

usage: oida [-h] [--version] [--bug] [--no-bug-report] [-v] [-t THREADS] [--debug] [-c FILE] [-o DIR]
            [--format {json,csv,console,all}] [-q] [-W] [--json-log FILE]
            <protocol> ...

O.I.D.A. = OT / ICS Dynamic Assessment framework

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --bug                 Print diagnostic info for bug reports
  --no-bug-report       Suppress the crash bug-report block on unexpected internal errors (also honors
                        OIDA_NO_BUG_REPORT=1)
  -v, --verbose         Increase verbosity (-v, -vv, -vvv)
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 10)
  --debug               Enable debug output
  -c FILE, --config FILE
                        Load scan configuration from YAML or JSON file

Output Options:
  -o DIR, --output DIR  Output directory for exported results (<protocol>.json/csv, plus per-table CSVs where
                        available; default format: all)
  --format {json,csv,console,all}
                        Output format (default: console)
  -q, --quiet           Suppress console output
  -W, --full-width      Show full-width tables without truncating to terminal width
  --json-log FILE       Write structured JSON log events to FILE (NDJSON format, one object per line)

OT / industrial
  ads                   ads protocol (run 'oida ads -h' for options)
  bacnet                bacnet protocol (run 'oida bacnet -h' for options)
  can                   can protocol (run 'oida can -h' for options)
  dnp3                  dnp3 protocol (run 'oida dnp3 -h' for options)
  ethercat              ethercat protocol (run 'oida ethercat -h' for options)
  ethernetip            ethernetip protocol (run 'oida ethernetip -h' for options)
  goose                 goose protocol (run 'oida goose -h' for options)
  hart                  hart protocol (run 'oida hart -h' for options)
  iec104                iec104 protocol (run 'oida iec104 -h' for options)
  knx                   knx protocol (run 'oida knx -h' for options)
  mms                   mms protocol (run 'oida mms -h' for options)
  modbus                modbus protocol (run 'oida modbus -h' for options)
  opcua                 opcua protocol (run 'oida opcua -h' for options)
  profinet              profinet protocol (run 'oida profinet -h' for options)
  snap7 (s7)            snap7 protocol (run 'oida snap7 -h' for options)
  tase2                 tase2 protocol (run 'oida tase2 -h' for options)

IoT / application
  coap                  coap protocol (run 'oida coap -h' for options)
  mqtt                  mqtt protocol (run 'oida mqtt -h' for options)
  ocpp                  ocpp protocol (run 'oida ocpp -h' for options)
  snmp                  snmp protocol (run 'oida snmp -h' for options)

Healthcare
  astm                  astm protocol (run 'oida astm -h' for options)
  dicom                 dicom protocol (run 'oida dicom -h' for options)
  fhir                  fhir protocol (run 'oida fhir -h' for options)
  hl7                   hl7 protocol (run 'oida hl7 -h' for options)

Discovery & tooling
  discovery (discover)  discovery protocol (run 'oida discovery -h' for options)
  fuzz                  Protocol fuzzing (boofuzz-based)
  pcap                  pcap protocol (run 'oida pcap -h' for options)
  serial                Serial port utilities (list ports, auto-detect parameters)

Run oida <protocol> -h for protocol-specific options
```
We can see all the protocols supported by OIDA, we decided to start with modbus.

## Detection engineering

- [Modbus/TCP Purple Team Detection Engineering](modbus/README.md) documents
  the OIDA function-code fuzzing attack, MBAP/PDU packet structure,
  Suricata 7.0.3 rules, PCAP replay, and tuning guidance.

## Mock OT

We used the official [shooting range](https://getoida.dev/features/simulation-services/) tutorial on OIDA's documentation to emulate our attack.

```shell
git clone https://github.com/f0rw4rd/oida
cd oida

# Start the everyday protocol mocks (builds images on first run)
python services.py up core

# See what is running and on which ports
python services.py status
python services.py ports

# Tear it all down
python services.py down
```
