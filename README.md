# SrvHide
Simple tool to dump/hide services in `services.exe` process. Once hid the service won't show in `services.msc`. The tool is based on [this](https://www.codeproject.com/Articles/46670/Service-Hiding) blogpost.

## Results
```
C:\Users\john-vm\Desktop\srvhide>srvhide.exe -d
[+] Services.exe PID: 664
[+] Check driver loaded: Success
[+] Protect current process: Success
[*] Services.exe - 0x7ff68a3f0000 - 0xb0000
[+] g_ServicesDB location - 0x7ff68a4905b8
[+] g_ServicesDB - 0x2325260ec70
[*] 0x2325260ec70 - 1394ohci
[*] 0x2325260f030 - 3ware
[*] 0x2325260f4b0 - AarSvc
[*] 0x2325260f690 - ACPI
[*] 0x2325260f8d0 - AcpiDev
...
[*] 0x232528fa420 - UserDataSvc_80c26
[*] 0x232528fa9f0 - WpnUserService_80c26
[*] 0x232528f65b0 - MpKslb488759d
```

```
C:\Users\john-vm\Desktop\srvhide>srvhide.exe -s 3ware
[+] Services.exe PID: 648
[+] Check driver loaded: Success
[+] Protect current process: Success
[*] Services.exe - 0x7ff7ecb70000 - 0xb0000
[+] g_ServicesDB location - 0x7ff7ecc105b8
[+] g_ServicesDB - 0x1f87a40e830
[+] Match found. Removing..
```

## Disclaimer
This tool is just a proof of concept develped while learning how windows stores service information.
The `services.exe` is a protected process (`PPL`) and can not be tampered simply from usermode. `SrvHide` uses `BlackBone` driver for reading/writing target process memory.

## Build
```
git clone --recurse-submodules https://github.com/archercreat/srvhide.git
cd srvhide
cmake -B build
cmake --build build
```

Once built, copy `BlackBoneDrv10.sys` to `srvhide.exe` directory.

## Usage

```
.\build\Debug\srvhide.exe
Usage: SrvHide: Hide service in services.exe [options]

Optional arguments:
-h --help       shows help message and exits
-v --version    prints version information and exits
-s --service    Service name to hide [default: ""]
-d --dump       Dump services database [default: false]
```
