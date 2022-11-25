# Abstract

The _etwmon_ plug-in detects various etw-related modifications in windows kernel.

## Description

List of things etwmon monitors:

* Global ETW handles: `EtwpPsProvRegHandle`, `EtwpRegTraceHandle`, etc
* Global ETW Callback pointers: `EtwpDiskIoNotifyRoutines`, `EtwpFileIoNotifyRoutines`, etc
* ETW Loggers: `GetCPUClock` aka `infinity hook` technique, `CallbackContext`
* ETW Providers: `ProviderEnableInfo`, etc

Checks are made at the end of analysis and don't affect vm performance.
