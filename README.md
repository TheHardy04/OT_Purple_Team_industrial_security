# OT Purple Team Industrial Security

This project provides a practical environment for exploring industrial and
operational technology (OT) security with [O.I.D.A.](https://getoida.dev),
the OT/ICS Dynamic Assessment framework.

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
