# SrvHide
Simple tool to dump/hide services from `services.exe` process. Once hid the service won't show in `services.msc`. The tool is based on [this](https://www.codeproject.com/Articles/46670/Service-Hiding) blogpost.

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