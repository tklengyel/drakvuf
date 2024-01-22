# Abstract

The _rootkitmon_ plug-in detects various rootkit techniques in kernel.

## Description

List of things rootkitmon monitors:

* `IDT`, `GDT` tables
* `GDTR`, `IDTR`, `LSTAR` registers
* `nonpaged, non writtable driver code sections`
* `DriverOjbect, DeviceObject chain`
* `FwpmCalloutAdd0` and `FltRegisterFilter` functions
* `HalPrivateDispatchTable`
* `g_CiEnabled` and `g_CiCallbacks`
* `ObjectCallbacks` and `ObjectType` callbacks
