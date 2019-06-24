#include<ntddk.h>
#include<wdf.h>

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD DummyDriverEvtDeviceAdd;

_declspec(dllexport) int add1(int in) {
	DbgPrint("In DummyDriver!noError");
	return in+1;
}

_declspec(dllexport) int sub1(int in) {
	DbgPrint("In DummyDriver!error");
	if (in > 10)
	{
		if (in < 15)
		{
			KeBugCheck(0xEFFFEFFF);
		}
	}
	return in-1;
}
/*
VOID DummyDriverIoRead(WDFQUEUE q, WDFREQUEST req, size_t len)
{
	UNREFERENCED_PARAMETER(q);
	DbgPrint("In Dummy Driver Read\n");
	WdfRequestCompleteWithInformation(req, STATUS_SUCCESS, len);
}

VOID DummyDriverIoWrite(WDFQUEUE q, WDFREQUEST req, size_t len)
{
	UNREFERENCED_PARAMETER(q);
	DbgPrint("In Dummy Driver write\n");
	WdfRequestCompleteWithInformation(req, STATUS_SUCCESS, len);
}
*/
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDF_DRIVER_CONFIG config;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Dummy HelloWorld: 2DriverEntry\n"));
	WDF_DRIVER_CONFIG_INIT(&config,
		DummyDriverEvtDeviceAdd);
	status = WdfDriverCreate(DriverObject,
		RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES,
		&config,
		WDF_NO_HANDLE);
	
	return status;
}

NTSTATUS DummyDriverEvtDeviceAdd(
	_In_ WDFDRIVER Driver,
	_Inout_ PWDFDEVICE_INIT DeviceInit
)
{
	UNREFERENCED_PARAMETER(Driver);
	NTSTATUS status;
	WDFDEVICE hDevice;
	//WDF_OBJECT_ATTRIBUTES objAttributes;
	//WDF_IO_QUEUE_CONFIG ioCallBacks;

	//DECLARE_CONST_UNICODE_STRING(ntDeviceName, L"\\device\\DummyDriver");
	//DECLARE_CONST_UNICODE_STRING(dosDeviceName, L"\\DosDevices\\DummyDriver");

	//WDF_OBJECT_ATTRIBUTES_INIT(&objAttributes);

	//WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&objAttributes, NOTHING);

	//status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);
	/*
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WdfDeviceInitAssignNameFailed");
		return status;
	}
	*/
	DbgPrint("DummyDriver: HelloWorld: EVT_Device_Add");
	status = WdfDeviceCreate(&DeviceInit,
		WDF_NO_OBJECT_ATTRIBUTES,
		&hDevice
	);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("device create failed");
		return status;
	}
	/*
	status = WdfDeviceCreateSymbolicLink(hDevice,
		&dosDeviceName);
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioCallBacks,
		WdfIoQueueDispatchSequential);

	ioCallBacks.EvtIoRead = DummyDriverIoRead;
	ioCallBacks.EvtIoWrite = DummyDriverIoWrite;

	status = WdfIoQueueCreate(hDevice,
		&ioCallBacks,
		WDF_NO_OBJECT_ATTRIBUTES,
		NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPri
		nt("queue create failed");
		return status;
	}
	*/
	return status;
}


