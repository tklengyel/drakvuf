# Abstract

The _callbackmon_ plug-in detects overwritten/deleted/added callbacks in various kernel structures.

## Description

The plug-in collects already installed callbacks at the beginning of the analysis and compares them with the snapshot, created at the end of analysis.

List of structures that callbackmon currently monitors:

* `PspCreateProcessNotifyRoutine`
* `PspCreateThreadNotifyRoutine`
* `PspLoadImageNotifyRoutine`
* `KeBugCheckCallbackListHead`
* `KeBugCheckReasonCallbackListHead`
* `CallbackListHead`
* `SeFileSystemNotifyRoutinesHead`
* `PopRegisteredPowerSettingCallbacks`
* `IopNotifyShutdownQueueHead`
* `IopNotifyLastChanceShutdownQueueHead`
* `RtlpDebugPrintCallbackList`
* `IopFsNotifyChangeQueueHead`
* `IopDriverReinitializeQueueHead`
* `IopBootDriverReinitializeQueueHead`
* `KiNmiCallbackListHead`
* `IopUpdatePriorityCallbackRoutine`
* `PnpProfileNotifyList`
* `PnpDeviceClassNotifyList`
* `EmpCallbackListHead`
* `PsWin32CallBack`
* `netio.sys gWfpGlobal callbacks`