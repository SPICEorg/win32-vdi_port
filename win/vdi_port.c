/*
   Copyright (C) 2009 Red Hat, Inc.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <wdmguid.h>

#include "vdi_dev.h"

#define USE_REMOVE_LOCK

#define DEBUG_PRINT(arg) DebugPrint arg

#define DEVICE_NAME L"\\Device\\VDIPort"
#define DOS_DEVICE_NAME L"\\DosDevices\\VDIPort"
#define DRIVER_NAME "VDIPort"
#define TEMP_BUFFER_SIZE 1024

#define VDIPORT_ALLOC_TAG 'pidv'

#define DBG_LEVEL 1

#define MIN(a, b) (((a) > (b)) ? (b) : (a))

#define VDIPORT_ERR_ERROR -1
#define VDIPORT_ERR_RESET -2
#define VDIPORT_ERR_IO_ERROR -3

typedef enum {
    PASSIVE,
    STARTING,
    STARTED,
    STOPPING,
    STOPED,
    SURPRISE,
    REMOVING,
    REMOVED,
} PnPState;

typedef struct VDIPortExt {
    DEVICE_OBJECT *physical;
    DEVICE_OBJECT *device;
    UNICODE_STRING interface_name;
    DEVICE_OBJECT *lower_dev;
    PnPState pnp_state;
    PnPState previos_pnp_state;
    BUS_INTERFACE_STANDARD bus_interface;
    PKINTERRUPT interrupt;
    PUCHAR io_base;
    PULONG notify_port;
    PULONG connection_port;
    PULONG irq_port;
    ULONG mem_length;
    VDIPortRam *ram;
    UINT32 generation;
    UINT32 read_pos;
    PKEVENT user_event;
    KSPIN_LOCK event_lock;
    LONG exclusive_gurd;
#ifdef USE_REMOVE_LOCK
    IO_REMOVE_LOCK remove_lock;
#endif
} VDIPortExt;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT  driver, IN PUNICODE_STRING registry_path);
NTSTATUS VDIPortAddDevice(IN PDRIVER_OBJECT device, IN PDEVICE_OBJECT physical);
NTSTATUS VDIPortCreate(IN PDEVICE_OBJECT device, IN PIRP irp);
NTSTATUS VDIPortClose(IN PDEVICE_OBJECT device, IN PIRP irp);
NTSTATUS VDIPortDispatchPnP(IN PDEVICE_OBJECT  device, IN PIRP irp);
NTSTATUS VDIPortDeviceControl(IN PDEVICE_OBJECT device, IN PIRP irp);
NTSTATUS VDIPortSystemControl(IN PDEVICE_OBJECT device, IN PIRP irp);
NTSTATUS VDIPortPower(IN PDEVICE_OBJECT device, IN PIRP irp);
VOID VDIPortUnload(IN PDRIVER_OBJECT driver);

NTSTATUS VDIPortRead(IN PDEVICE_OBJECT device, IN PIRP irp);
NTSTATUS VDIPortWrite(IN PDEVICE_OBJECT device, IN PIRP irp);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, VDIPortUnload)
#pragma alloc_text (PAGE, VDIPortAddDevice)
#pragma alloc_text (PAGE, VDIPortCreate)
#pragma alloc_text (PAGE, VDIPortClose)
#pragma alloc_text (PAGE, VDIPortDispatchPnP)
#endif


//c77a1bf4-6901-4aae-9ca5-ff3b984a7598
static GUID GUID_DEVINTERFACE_VDI_PORT = {0xc77a1bf4, 0x6901, 0x4aae,
                                           { 0x9c, 0xa5, 0xff, 0x3b, 0x98, 0x4a, 0x75, 0x98}};

static GUID GUID_SYSCLASS = {0x4d36e97d, 0xe325, 0x11ce,
                                           { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};


static void DebugPrint(int level, const char *message, ...)
{
    NTSTATUS status;
    UCHAR buf[1024];
    va_list ap;

    if (level > DBG_LEVEL) {
        return;
    }
    va_start(ap, message);
    status = RtlStringCbVPrintfA(buf, sizeof(buf), message, ap);
    if(!NT_SUCCESS(status)) {
        KdPrint((DRIVER_NAME": sprintf error"));
    } else {
        KdPrint((DRIVER_NAME":%s", buf));
    }
    va_end(ap);
}

static void RingCleanup(VDIPortExt *ext)
{
    VDIPortRing *ring = &ext->ram->output;
    int do_notify = FALSE;

    while (!RING_IS_EMPTY(ring)) {
        VDIPortPacket *packet;
        int notify = FALSE;
        packet = RING_CONS_ITEM(ring);
        if (packet->gen < ext->generation || (packet->gen - ext->generation) > (1U << 31)) {
            RING_POP(ring, notify);
            do_notify = notify || do_notify;
        } else {
            break;
        }
    }
    if (do_notify) {
         WRITE_PORT_ULONG(ext->notify_port, 0);
    }
    ext->read_pos = 0;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT  driver, IN PUNICODE_STRING registry_path)
{
    DEBUG_PRINT((3, "%s: start\n", __FUNCTION__));

    driver->MajorFunction[IRP_MJ_PNP] = VDIPortDispatchPnP;
    driver->MajorFunction[IRP_MJ_CREATE]= VDIPortCreate;
    driver->MajorFunction[IRP_MJ_CLOSE] = VDIPortClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VDIPortDeviceControl;
    driver->MajorFunction[IRP_MJ_READ] = VDIPortRead;
    driver->MajorFunction[IRP_MJ_WRITE] = VDIPortWrite;
    driver->MajorFunction[IRP_MJ_POWER] = VDIPortPower;
    //driver->MajorFunction[IRP_MJ_CLEANUP]= ;
    driver->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = VDIPortSystemControl;
    driver->DriverExtension->AddDevice = VDIPortAddDevice;
    driver->DriverUnload = VDIPortUnload;

    DEBUG_PRINT((4, "%s: done\n", __FUNCTION__));
    return STATUS_SUCCESS;
}

VOID VDIPortUnload(IN PDRIVER_OBJECT driver)
{
    PAGED_CODE();
    DEBUG_PRINT((3, "%s start\n", __FUNCTION__));

    DEBUG_PRINT((4, "%s done\n", __FUNCTION__));
}

static NTSTATUS InitializeBusInterface(VDIPortExt *ext)
{
    KEVENT event;
    NTSTATUS status;
    PIRP irp;
    IO_STATUS_BLOCK status_block;
    PIO_STACK_LOCATION stack;
    PDEVICE_OBJECT device;

    PAGED_CODE();

    DEBUG_PRINT((6, "%s: start\n", __FUNCTION__));

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    device = IoGetAttachedDeviceReference(ext->device);

    irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, device, NULL,
                                        0, NULL, &event, &status_block);
    if (irp == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto error_1;
    }

    stack = IoGetNextIrpStackLocation(irp);
    stack->MinorFunction = IRP_MN_QUERY_INTERFACE;
    stack->Parameters.QueryInterface.InterfaceType = (LPGUID)&GUID_BUS_INTERFACE_STANDARD;
    stack->Parameters.QueryInterface.Size = sizeof(BUS_INTERFACE_STANDARD);
    stack->Parameters.QueryInterface.Version = 1;
    stack->Parameters.QueryInterface.Interface = (PINTERFACE)&ext->bus_interface;
    stack->Parameters.QueryInterface.InterfaceSpecificData = NULL;
    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(device, irp);
    if (status == STATUS_PENDING) {
        status = KeWaitForSingleObject( &event, Executive, KernelMode, FALSE, NULL);
        ASSERT(NT_SUCCESS(status));
        status = status_block.Status;
    }

error_1:
    ObDereferenceObject(device);

    DEBUG_PRINT((7, "%s: done\n", __FUNCTION__));
    return status;
}

NTSTATUS VDIPortAddDevice(IN PDRIVER_OBJECT driver, IN PDEVICE_OBJECT physical_device)
{
    NTSTATUS status;
    DEVICE_OBJECT *device;
    DEVICE_OBJECT *lower_dev;
    VDIPortExt *ext;
    UNICODE_STRING name;
    UNICODE_STRING win32_name;

    PAGED_CODE();

    DEBUG_PRINT((3, "%s: start\n", __FUNCTION__));
    RtlInitUnicodeString(&name, DEVICE_NAME);
    status = IoCreateDevice(driver, sizeof(*ext), &name, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, TRUE, &device);

    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT((0, "%s: create device failed %u\n", __FUNCTION__, status));
        return status;
    }

    RtlInitUnicodeString(&win32_name, DOS_DEVICE_NAME );
    IoCreateSymbolicLink(&win32_name, &name);

    ext = device->DeviceExtension;
    RtlZeroMemory(ext, sizeof(*ext));
    ext->device = device;
    ext->physical = physical_device;
    ext->pnp_state = PASSIVE;
    KeInitializeSpinLock(&ext->event_lock);
#ifdef USE_REMOVE_LOCK
    IoInitializeRemoveLock(&ext->remove_lock, VDIPORT_ALLOC_TAG, 0, 0);
#endif

    device->Flags |= DO_POWER_PAGABLE | DO_BUFFERED_IO;

    lower_dev = IoAttachDeviceToDeviceStack(device, physical_device);

    if (!lower_dev) {
        DEBUG_PRINT((0, "%s: attach device failed %u\n", __FUNCTION__));
        goto error_1;
    }

    ext->lower_dev = lower_dev;

    status = InitializeBusInterface(ext);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT((0, "%s: init bus interface failed %u\n", __FUNCTION__, status));
        goto error_2;
    }

    status = IoRegisterDeviceInterface(physical_device, &GUID_DEVINTERFACE_VDI_PORT,
                                       NULL, &ext->interface_name);

    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT((0, "%s: register interface failed %u\n", __FUNCTION__, status));
        goto error_2;
    }

    device->Flags &= ~DO_DEVICE_INITIALIZING;

    DEBUG_PRINT((4, "%s: done\n", __FUNCTION__));

    return STATUS_SUCCESS;

error_2:
    IoDetachDevice(ext->lower_dev);

error_1:

    IoDeleteDevice(device);
    return status;
}

static NTSTATUS IoIncrement(VDIPortExt *ext)
{
#ifdef USE_REMOVE_LOCK
    return IoAcquireRemoveLock(&ext->remove_lock, NULL);
#else
    return STATUS_SUCCESS;
#endif
}

static void IoDecrement(VDIPortExt *ext)
{
#ifdef USE_REMOVE_LOCK
    IoReleaseRemoveLock(&ext->remove_lock, NULL);
#endif
}

NTSTATUS VDIPortCreate(IN PDEVICE_OBJECT device, IN PIRP irp)
{
    PIO_STACK_LOCATION stack;
    VDIPortExt *ext;
    NTSTATUS status;
    LONG gurd_val;

    PAGED_CODE();

    DEBUG_PRINT((3, "%s: start\n", __FUNCTION__));

    ext = (VDIPortExt *)device->DeviceExtension;
    status = IoIncrement(ext);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT((0, "%s: io increment failed\n", __FUNCTION__));
        goto error_1;
    }

    stack = IoGetCurrentIrpStackLocation(irp);

    if (stack->FileObject->FileName.Length != 0) {
        DEBUG_PRINT((0, "%s: has name\n", __FUNCTION__));
        status = STATUS_INVALID_PARAMETER;
        goto error_2;
    }

    gurd_val = InterlockedExchange(&ext->exclusive_gurd, 1);
    if (gurd_val) {
        DEBUG_PRINT((0, "%s: device is busy\n", __FUNCTION__));
        status = STATUS_DEVICE_BUSY;
        goto error_2;
    }

#ifndef USE_REMOVE_LOCK
    if (ext->pnp_state == REMOVED) {
        DEBUG_PRINT((0, "%s: REMOVED\n", __FUNCTION__));
        status = STATUS_NO_SUCH_DEVICE ;
        goto error_2;
    }
#endif

    ext->generation = READ_PORT_ULONG(ext->connection_port);
    RingCleanup(ext);

error_2:
    IoDecrement(ext);

error_1:
    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    DEBUG_PRINT((4, "%s: done\n", __FUNCTION__));
    return status;
}

static void SetUserEvent(VDIPortExt *ext, PKEVENT user_event)
{
    if (ext->user_event) {
        PKEVENT old_event;
        KIRQL irql;

        KeAcquireSpinLock(&ext->event_lock, &irql);
        old_event = ext->user_event;
        ext->user_event = NULL;
        KeReleaseSpinLock(&ext->event_lock, irql);
        ObDereferenceObject(old_event);
    }
    if ((ext->user_event = user_event)) {
        ext->ram->int_mask = ~0;
    } else {
        ext->ram->int_mask = 0;
    }
    WRITE_PORT_ULONG(ext->irq_port, 0);
}

NTSTATUS VDIPortClose(IN PDEVICE_OBJECT device, IN PIRP irp)
{
    PIO_STACK_LOCATION stack;
    VDIPortExt *ext;
    NTSTATUS status;
    LONG gurd_val;

    PAGED_CODE();

    DEBUG_PRINT((3, "%s: start\n", __FUNCTION__));
    stack = IoGetCurrentIrpStackLocation(irp);
    ext = (VDIPortExt *)device->DeviceExtension;
    status = IoIncrement(ext);
    ASSERT(NT_SUCCESS(status));
    SetUserEvent(ext, NULL);
    WRITE_PORT_ULONG(ext->connection_port, 0);

    status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    if ((gurd_val = InterlockedExchange(&ext->exclusive_gurd, 0)) == 0) {
        DEBUG_PRINT((0, "%s: gurd val was zero\n", __FUNCTION__));
    }
    IoDecrement(ext);
    DEBUG_PRINT((4, "%s: done\n", __FUNCTION__));
    return status;
}

typedef struct ScheduleContext {
    PIO_WORKITEM item;
    VOID *arg1;
    VOID *arg2;
} ScheduleContext;


#ifdef ALLOC_PRAGMA
static NTSTATUS Prob(VDIPortExt *ext, PIRP irp);
#pragma alloc_text (PAGE, Prob)
#endif
static NTSTATUS Prob(VDIPortExt *ext, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PCI_COMMON_CONFIG  pci_config;
    ULONG n;

    PAGED_CODE();

    DEBUG_PRINT((9, "%s: start\n", __FUNCTION__));

    n = ext->bus_interface.GetBusData(ext->bus_interface.Context, PCI_WHICHSPACE_CONFIG,
                                      &pci_config, 0, sizeof(pci_config));

    if (n != sizeof(pci_config)) {
        DEBUG_PRINT((0, "%s: read pci config failed\n", __FUNCTION__));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (pci_config.VendorID != REDHAT_PCI_VENDOR_ID ||
                            pci_config.DeviceID != VDI_PORT_DEVICE_ID) {
        DEBUG_PRINT((0, "%s: invalid pci device. vendor 0x%x id 0x%x\n",
                    __FUNCTION__,
                    (ULONG)pci_config.VendorID,
                    (ULONG)pci_config.DeviceID));
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }
    if (pci_config.RevisionID != VDI_PORT_REVISION) {
        DEBUG_PRINT((0, "%s: bad revision 0x%x expect 0x%x\n",
                    __FUNCTION__,
                    (ULONG)pci_config.RevisionID,
                    VDI_PORT_REVISION));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    return STATUS_SUCCESS;

}

static VOID DcpForIsr(IN PKDPC dpc, IN PDEVICE_OBJECT device,
               IN PIRP irp, IN PVOID context)
{
    VDIPortExt *ext = (VDIPortExt *)context;
    KIRQL irql;

    UINT32 pending = InterlockedExchange(&ext->ram->int_pending, 0);
    KeAcquireSpinLock(&ext->event_lock, &irql);
    if (ext->user_event) {
        KeSetEvent(ext->user_event, IO_MOUSE_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&ext->event_lock, irql);
    ext->ram->int_mask = ~0;
    WRITE_PORT_ULONG(ext->irq_port, 0);
}

BOOLEAN InterruptHandler(IN PKINTERRUPT interrupt, IN PVOID context)
{
    VDIPortExt *ext = (VDIPortExt *)context;

    if (!(ext->ram->int_pending & ext->ram->int_mask)) {
        return FALSE;
    }
    ext->ram->int_mask = 0;
    WRITE_PORT_ULONG(ext->irq_port, 0);
    IoRequestDpc(ext->device, NULL, ext);
    return TRUE;
}

#ifdef ALLOC_PRAGMA
static void ReleaseHardwareRes(VDIPortExt *ext);
#pragma alloc_text (PAGE, ReleaseHardwareRes)
#endif
static void ReleaseHardwareRes(VDIPortExt *ext)
{
    PAGED_CODE();

    if (ext->ram) {
        MmUnmapIoSpace(ext->ram, ext->mem_length);
        ext->ram = NULL;
        ext->mem_length = 0;
    }
    if (ext->interrupt) {
        IoDisconnectInterrupt(ext->interrupt);
        ext->interrupt = NULL;
    }
}

#ifdef ALLOC_PRAGMA
static NTSTATUS InitHwResources(VDIPortExt *ext, PIRP irp);
#pragma alloc_text (PAGE, InitHwResources)
#endif
NTSTATUS InitHwResources(VDIPortExt *ext, PIRP irp)
{
    PCM_PARTIAL_RESOURCE_LIST resource_list;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR descriptor;
    PIO_STACK_LOCATION stack;
    BOOLEAN io_present = FALSE;
    BOOLEAN mem_present = FALSE;
    BOOLEAN int_present = FALSE;
    NTSTATUS status;
    UINT32 i;

    PAGED_CODE();

    DEBUG_PRINT((9, "%s: start\n", __FUNCTION__));

    stack = IoGetCurrentIrpStackLocation(irp);

    if (!stack->Parameters.StartDevice.AllocatedResourcesTranslated) {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    resource_list =
          &stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList;

    descriptor = &resource_list->PartialDescriptors[0];

    for (i = 0; i < resource_list->Count; i++, descriptor++) {
        switch (descriptor->Type) {
        case CmResourceTypePort:
            DEBUG_PRINT((11, "%s: io base %x length %d\n",
                        __FUNCTION__,
                        descriptor->u.Port.Start.LowPart,
                        descriptor->u.Port.Length));

            if (io_present || descriptor->u.Port.Length < VDI_PORT_IO_RANGE_SIZE) {
                status = STATUS_DEVICE_CONFIGURATION_ERROR;
                goto error;
            }
            ext->io_base = (PUCHAR)ULongToPtr(descriptor->u.Port.Start.LowPart);
            ext->connection_port = (PULONG)(ext->io_base + VDI_PORT_IO_CONNECTION);
            ext->notify_port = (PULONG)(ext->io_base + VDI_PORT_IO_NOTIFY);
            ext->irq_port = (PULONG)(ext->io_base + VDI_PORT_IO_UPDATE_IRQ);

            io_present = TRUE;
            break;

        case CmResourceTypeMemory:
            DEBUG_PRINT((11, "%s: mem base 0x%llx length %u\n",
                        __FUNCTION__,
                        (UINT64)descriptor->u.Memory.Start.QuadPart,
                        descriptor->u.Memory.Length));

            if (mem_present || descriptor->u.Memory.Length < sizeof(VDIPortRam)) {
                status = STATUS_DEVICE_CONFIGURATION_ERROR;
                goto error;
            }

            ext->mem_length = descriptor->u.Memory.Length,
            ext->ram = (VDIPortRam *)MmMapIoSpace(descriptor->u.Memory.Start, ext->mem_length,
                                                  MmCached);
            if (ext->ram->magic != VDI_PORT_MAGIC) {
                DEBUG_PRINT((0, "%s: bad magic 0x%x 0x%x\n", __FUNCTION__, ext->ram->magic,
                             VDI_PORT_MAGIC));
                status = STATUS_DEVICE_CONFIGURATION_ERROR;
                goto error;
            }
            ext->ram->int_mask = 0;
            mem_present = TRUE;
            break;

        case CmResourceTypeInterrupt:
            DEBUG_PRINT((11, "%s: interrupt vector 0x%x level 0x%x affinity 0x%x\n",
                        __FUNCTION__,
                        descriptor->u.Interrupt.Vector,
                        descriptor->u.Interrupt.Level,
                        (ULONG)descriptor->u.Interrupt.Affinity));

            if (int_present) {
                DEBUG_PRINT((0, "%s: interrupt is present\n", __FUNCTION__));
                status = STATUS_DEVICE_CONFIGURATION_ERROR;
                goto error;
            }
            ASSERT(!(descriptor->Flags & CM_RESOURCE_INTERRUPT_LATCHED));

            IoInitializeDpcRequest(ext->device, DcpForIsr);
            status = IoConnectInterrupt(&ext->interrupt,
                                        InterruptHandler,
                                        ext,
                                        NULL,
                                        descriptor->u.Interrupt.Vector,
                                        (UCHAR)descriptor->u.Interrupt.Level,
                                        (UCHAR)descriptor->u.Interrupt.Level,
                                        LevelSensitive,
                                        TRUE,
                                        descriptor->u.Interrupt.Affinity,
                                        FALSE);
            if (!NT_SUCCESS(status)) {
                DEBUG_PRINT((0, "%s: connect interrupt failed\n", __FUNCTION__));
                goto error;
            }
            int_present = TRUE;
            break;

        default:
            DEBUG_PRINT((11, "%s: other type\n", __FUNCTION__));
            break;
        }
    }

    if (!int_present || !mem_present || !io_present) {
        status = STATUS_DEVICE_CONFIGURATION_ERROR;
        goto error;
    }

    return STATUS_SUCCESS;

error:
    ReleaseHardwareRes(ext);
    return STATUS_DEVICE_CONFIGURATION_ERROR;
}

static VOID StartDevice(IN PDEVICE_OBJECT device, ScheduleContext *context)
{
    PIO_STACK_LOCATION stack;
    NTSTATUS  status;
    VDIPortExt *ext;
    PIRP irp;

    PAGED_CODE();

    DEBUG_PRINT((6, "%s: start\n", __FUNCTION__));

    ext = (VDIPortExt *) device->DeviceExtension;
    irp = (PIRP)context->arg1;
    stack = IoGetCurrentIrpStackLocation(irp);

    status = Prob(ext, irp);
    if(NT_SUCCESS(status)) {
        status = InitHwResources(ext, irp);
    }

    if(NT_SUCCESS(status)) {
        ext->pnp_state = STARTED;
        IoSetDeviceInterfaceState(&ext->interface_name, TRUE);
    } else {
        ext->pnp_state = PASSIVE;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    IoDecrement(ext);

    IoFreeWorkItem(context->item);
    ExFreePool(context);
    DEBUG_PRINT((7, "%s: done 0x%x\n", __FUNCTION__, status));
    return;
}

NTSTATUS ScheduleWorkItem(PDEVICE_OBJECT device, PIO_WORKITEM_ROUTINE callback,
                          VOID *arg1, VOID *arg2)
{
    PIO_WORKITEM item = NULL;
    ScheduleContext *context;

    context = ExAllocatePoolWithTag(NonPagedPool, sizeof(ScheduleContext),
                                    VDIPORT_ALLOC_TAG);

    if (!context) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    item = IoAllocateWorkItem(device);

    if (!item) {
        ExFreePoolWithTag(context, VDIPORT_ALLOC_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    context->item = item;
    context->arg1 = arg1;
    context->arg2 = arg2;

    IoQueueWorkItem(item, callback, DelayedWorkQueue, context);

    return STATUS_SUCCESS;
}

static NTSTATUS StartCompletion(IN PDEVICE_OBJECT device, IN PIRP irp, IN PVOID context)
{
    NTSTATUS status;

    status = ScheduleWorkItem(device, StartDevice, irp, NULL);
    if(!NT_SUCCESS(status)) {
        irp->IoStatus.Status = status;
        IoDecrement((VDIPortExt *)device->DeviceExtension);
        return STATUS_CONTINUE_COMPLETION;
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}


static NTSTATUS CallNext(VDIPortExt *ext, IN PIRP irp)
{
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(irp);
    IoDecrement(ext);
    return IoCallDriver(ext->lower_dev, irp);
}

NTSTATUS VDIPortDispatchPnP(IN PDEVICE_OBJECT device, IN PIRP irp)
{
    PIO_STACK_LOCATION stack;
    VDIPortExt *ext;
    NTSTATUS status;

    PAGED_CODE();

    DEBUG_PRINT((3, "%s: start\n", __FUNCTION__));

    stack = IoGetCurrentIrpStackLocation(irp);
    ext = device->DeviceExtension;
    status = IoIncrement(ext);

    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT((0, "%s: o increment failed\n", __FUNCTION__));
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        IoDecrement(ext);
        return status;
    }

#ifndef USE_REMOVE_LOCK
    if (ext->pnp_state == REMOVED) {
        DEBUG_PRINT((0, "%s: removed\n", __FUNCTION__));
        irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        IoDecrement(ext);
        return STATUS_NO_SUCH_DEVICE;
    }
#endif

    switch (stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        DEBUG_PRINT((5, "%s: start device\n", __FUNCTION__));
        ext->pnp_state = STARTING;
        IoMarkIrpPending(irp);
        IoCopyCurrentIrpStackLocationToNext(irp);
        IoSetCompletionRoutine(irp, StartCompletion, ext, TRUE, TRUE, TRUE);
        IoCallDriver(ext->lower_dev, irp);
        return STATUS_PENDING;
    case IRP_MN_QUERY_STOP_DEVICE:
        DEBUG_PRINT((5, "%s: query stop\n", __FUNCTION__));
        ext->previos_pnp_state = ext->pnp_state;
        ext->pnp_state = STOPPING;
        return CallNext(ext, irp);
    case IRP_MN_CANCEL_STOP_DEVICE:
        DEBUG_PRINT((5, "%s: cancel stop\n", __FUNCTION__));
        ext->pnp_state = ext->previos_pnp_state;
        return CallNext(ext, irp);
    case IRP_MN_STOP_DEVICE:
        DEBUG_PRINT((5, "%s: stop\n", __FUNCTION__));
        ext->pnp_state = STOPED;
        return CallNext(ext, irp);
    case IRP_MN_QUERY_REMOVE_DEVICE:
        DEBUG_PRINT((5, "%s: query remove\n", __FUNCTION__));
        ext->previos_pnp_state = ext->pnp_state;
        ext->pnp_state = REMOVING;
        return CallNext(ext, irp);
    case IRP_MN_CANCEL_REMOVE_DEVICE:
        DEBUG_PRINT((5, "%s: cancel remove\n", __FUNCTION__));
        ext->pnp_state = ext->previos_pnp_state;
        return CallNext(ext, irp);
    case IRP_MN_SURPRISE_REMOVAL:
        DEBUG_PRINT((5, "%s: surprise remove\n", __FUNCTION__));
        ext->pnp_state = SURPRISE;
        ReleaseHardwareRes(ext);
        return CallNext(ext, irp);
    case IRP_MN_REMOVE_DEVICE: {
        NTSTATUS status;

        DEBUG_PRINT((5, "%s: remove\n", __FUNCTION__));
#ifdef USE_REMOVE_LOCK
        IoReleaseRemoveLockAndWait(&ext->remove_lock, NULL);
#endif
        ext->pnp_state = REMOVED;
        ReleaseHardwareRes(ext);
        KeFlushQueuedDpcs();
        IoSetDeviceInterfaceState(&ext->interface_name, FALSE);
        irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation (irp);
        status = IoCallDriver(ext->lower_dev, irp);
        IoDetachDevice(ext->lower_dev);
        IoDeleteDevice(device);
        return status;
    }
    default:
        DEBUG_PRINT((5, "%s: other \n", __FUNCTION__, (UINT32)stack->MinorFunction));
        irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(irp);
        IoDecrement(ext);
        return IoCallDriver(ext->lower_dev, irp);
    }
}

static LONG ReadFromDev(VDIPortExt *ext, ULONG n, UINT8 *buf)
{
    VDIPortRing *ring = &ext->ram->output;
    LONG actual_read = 0;
    int do_notify = FALSE;
    LONG error = 0;

    DEBUG_PRINT((6, "%s: start\n", __FUNCTION__));
    //todo: read all current ext->generation data before VDIPORT_ERR_RESET for reliable improvement
    //          also require change in generation handling in WriteToDev  maybe separate generation
    if (ext->ram->generation != ext->generation) {
        DEBUG_PRINT((1, "%s: rest from %u to %u\n", __FUNCTION__, ext->generation,
                     ext->ram->generation));
        ext->generation = ext->ram->generation;
        RingCleanup(ext);
        return VDIPORT_ERR_RESET;
    }
    while (n) {
        VDIPortPacket *packet;
        int notify = FALSE;
        UINT32 now;
        int wait;

        RING_CONS_WAIT(ring, wait);
        if (wait) {
            break;
        }
        packet = RING_CONS_ITEM(ring);
        if (packet->gen != ext->generation) {
            if (!actual_read) {
                if (ext->ram->generation == ext->generation) {
                    DEBUG_PRINT((0, "%s: bad packet packet %u ext %u dev %u\n",
                                __FUNCTION__,
                                packet->gen,
                                ext->generation,
                                ext->ram->generation));
                    error = VDIPORT_ERR_IO_ERROR;
                } else if (ext->ram->generation != ext->generation) {
                    DEBUG_PRINT((1, "%s: rest from %u to %u\n", __FUNCTION__, ext->generation,
                                 ext->ram->generation));
                    ext->generation = ext->ram->generation;
                    RingCleanup(ext);
                    error = VDIPORT_ERR_RESET;
                }
            }
            break;
        }
        if (packet->size > sizeof(packet->data)) {
            DEBUG_PRINT((0, "%s: bad packet size\n", __FUNCTION__, packet->size));
            return VDIPORT_ERR_IO_ERROR;
        }
        now = MIN(n, packet->size - ext->read_pos);
        memcpy(buf, packet->data + ext->read_pos, now);
        n -= now;
        buf += now;
        actual_read +=  now;
        if ((ext->read_pos += now) == packet->size) {
            ext->read_pos = 0;
            RING_POP(ring, notify);
            do_notify = do_notify || notify;
        }
    }
    if (do_notify) {
        WRITE_PORT_ULONG(ext->notify_port, 0);
    }
    DEBUG_PRINT((7, "%s: done\n", __FUNCTION__));
    return actual_read ? actual_read : error;
}

static LONG WriteToDev(VDIPortExt *ext, ULONG n, UINT8 *buf)
{
    VDIPortRing *ring = &ext->ram->input;
    LONG actual_write = 0;
    int do_notify = FALSE;

    DEBUG_PRINT((6, "%s: start\n", __FUNCTION__));
    if (ext->ram->generation != ext->generation) {
        DEBUG_PRINT((1, "%s: rest from %u to %u\n", __FUNCTION__, ext->generation,
                     ext->ram->generation));
        ext->generation = ext->ram->generation;
        RingCleanup(ext);
        return VDIPORT_ERR_RESET;
    }

    while (n) {
        VDIPortPacket *packet;
        int notify = FALSE;
        int wait;

        RING_PROD_WAIT(ring, wait);
        if (wait) {
            break;
        }

        packet = RING_PROD_ITEM(ring);
        packet->gen = ext->generation;
        packet->size = MIN(n, sizeof(packet->data));
        memcpy(packet->data, buf, packet->size);
        n -= packet->size;
        buf += packet->size;
        actual_write +=  packet->size;
        RING_PUSH(ring, notify);
        do_notify = do_notify || notify;
    }

    if (do_notify) {
        WRITE_PORT_ULONG(ext->notify_port, 0);
    }

    DEBUG_PRINT((6, "%s: done\n", __FUNCTION__));
    return actual_write;
}

NTSTATUS VDIPortRead(IN PDEVICE_OBJECT device, IN PIRP irp)
{
    PIO_STACK_LOCATION stack;
    VDIPortExt *ext;
    NTSTATUS status;
    UINT8 *buf;
    ULONG n;
    LONG r;

    DEBUG_PRINT((3, "%s:\n", __FUNCTION__));
    ext = device->DeviceExtension;
    status = IoIncrement(ext);
    ASSERT(NT_SUCCESS(status));
    stack = IoGetCurrentIrpStackLocation(irp);

    if (ext->pnp_state != STARTED) {
        DEBUG_PRINT((0, "%s: not active\n", __FUNCTION__));
    }

    n = stack->Parameters.Read.Length;
    buf = irp->AssociatedIrp.SystemBuffer;

    if ((r = ReadFromDev(ext, n, buf)) < 0) {
        switch (r) {
        case VDIPORT_ERR_RESET:
            DEBUG_PRINT((1, "%s: STATUS_CONNECTION_INVALID\n", __FUNCTION__));
            status = STATUS_CONNECTION_INVALID;
            break;
        case VDIPORT_ERR_IO_ERROR:
            DEBUG_PRINT((0, "%s: STATUS_IO_DEVICE_ERROR\n", __FUNCTION__));
            status = STATUS_IO_DEVICE_ERROR;
            break;
        default:
            DEBUG_PRINT((0, "%s: STATUS_UNSUCCESSFUL\n", __FUNCTION__));
            status = STATUS_UNSUCCESSFUL;
        };
        irp->IoStatus.Information = 0;
    } else {
        irp->IoStatus.Information = r;
        status = STATUS_SUCCESS;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    IoDecrement(ext);

    DEBUG_PRINT((4, "%s: done\n", __FUNCTION__));
    return status;
}

NTSTATUS VDIPortWrite(IN PDEVICE_OBJECT device, IN PIRP irp)
{
    PIO_STACK_LOCATION stack;
    VDIPortExt *ext;
    NTSTATUS status;
    UINT8 *buf;
    ULONG n;
    LONG r;

    DEBUG_PRINT((3, "%s:\n", __FUNCTION__));
    ext = device->DeviceExtension;
    status = IoIncrement(ext);
    ASSERT(NT_SUCCESS(status));
    stack = IoGetCurrentIrpStackLocation(irp);

    if (ext->pnp_state != STARTED) {
        DEBUG_PRINT((0, "%s: not active\n", __FUNCTION__));
    }

    n = stack->Parameters.Write.Length;
    buf = irp->AssociatedIrp.SystemBuffer;
    if ((r = WriteToDev(ext, n, buf)) < 0) {
        switch (r) {
        case VDIPORT_ERR_RESET:
            DEBUG_PRINT((1, "%s: STATUS_CONNECTION_INVALID\n", __FUNCTION__));
            status = STATUS_CONNECTION_INVALID;
            break;
        case VDIPORT_ERR_IO_ERROR:
            DEBUG_PRINT((0, "%s: STATUS_IO_DEVICE_ERROR\n", __FUNCTION__));
            status = STATUS_IO_DEVICE_ERROR;
            break;
        default:
            DEBUG_PRINT((0, "%s: STATUS_UNSUCCESSFUL\n", __FUNCTION__));
            status = STATUS_UNSUCCESSFUL;
        };
        irp->IoStatus.Information = 0;
    } else {
        irp->IoStatus.Information = r;
        status = STATUS_SUCCESS;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    IoDecrement(ext);

    DEBUG_PRINT((4, "%s: done\n", __FUNCTION__));
    return status;
}

#define FIRST_AVAIL_IO_FUNC 0x800
#define VDI_PORT_CTL_SET_EVENT_FUNC FIRST_AVAIL_IO_FUNC

#define IOCTL_VDI_PORT_SET_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, VDI_PORT_CTL_SET_EVENT_FUNC, METHOD_BUFFERED, FILE_ANY_ACCESS)


#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, VDIPortDeviceControl)
#endif
NTSTATUS VDIPortDeviceControl(IN PDEVICE_OBJECT device, IN PIRP irp)
{
    PIO_STACK_LOCATION stack;
    VDIPortExt *ext;
    NTSTATUS status;
    ULONG input_len;
    PCHAR input_buf;

    PAGED_CODE();

    DEBUG_PRINT((3, "%s: start\n", __FUNCTION__));

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DEBUG_PRINT((0, "%s: not passive\n", __FUNCTION__));
    }

    ext = device->DeviceExtension;
    status = IoIncrement(ext);
    ASSERT(NT_SUCCESS(status));
    stack = IoGetCurrentIrpStackLocation(irp);
    input_len = stack->Parameters.DeviceIoControl.InputBufferLength;
    input_buf = irp->AssociatedIrp.SystemBuffer;

    if (ext->pnp_state != STARTED) {
        DEBUG_PRINT((0, "%s: not active\n", __FUNCTION__));
    }

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_VDI_PORT_SET_EVENT: {
        HANDLE user_event;
        PKEVENT k_event;
        if (input_len != sizeof(HANDLE)) {
            status = STATUS_INVALID_PARAMETER;
            goto error;
        }

        DEBUG_PRINT((5, "%s: 0x%x\n", __FUNCTION__, stack->FileObject));

        user_event = *(HANDLE*)input_buf;
        if (user_event) {
            status = ObReferenceObjectByHandle(user_event, GENERIC_ALL, *ExEventObjectType,
                                               KernelMode, &k_event, NULL);
            if (!NT_SUCCESS(status)) {
                goto error;
            }
        }
        SetUserEvent(ext, k_event);
        break;
    }
    default:
        DEBUG_PRINT((5, "%s: other\n", __FUNCTION__));
        IoDecrement(ext);
        return IoCallDriver(ext->lower_dev, irp);
    }

error:
    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    IoDecrement(ext);
    return status;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, VDIPortPower)
#endif
NTSTATUS VDIPortPower(IN PDEVICE_OBJECT device, IN PIRP irp)
{
    PIO_STACK_LOCATION stack;
    VDIPortExt *ext;
    NTSTATUS status;

    PAGED_CODE();

    DEBUG_PRINT((3, "%s: start\n", __FUNCTION__));

    stack = IoGetCurrentIrpStackLocation(irp);
    ext = device->DeviceExtension;

    status = IoIncrement(ext);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT((0, "%s: io increment failed\n", __FUNCTION__));
        goto error_1;
    }

#ifndef USE_REMOVE_LOCK
    if (ext->pnp_state == REMOVED) {
        status = STATUS_NO_SUCH_DEVICE ;
        DEBUG_PRINT((0, "%s: REMOVED\n", __FUNCTION__));
        goto error_2;
    }
#endif

    switch (stack->MinorFunction) {
    case IRP_MN_SET_POWER: {
        POWER_STATE_TYPE type;
        POWER_STATE state;

        type = stack->Parameters.Power.Type;
        state = stack->Parameters.Power.State;
        DEBUG_PRINT((1, "%s: set type %d state %d\n",
                     __FUNCTION__,
                     type,
                     state));
        break;
    }
    case IRP_MN_QUERY_POWER:
        break;
    };

    PoStartNextPowerIrp(irp);
    IoSkipCurrentIrpStackLocation(irp);
    status = PoCallDriver(ext->lower_dev, irp);
    DEBUG_PRINT((4, "%s: done\n", __FUNCTION__));
    IoDecrement(ext);
    return status;

#ifndef USE_REMOVE_LOCK
error_2:
    IoDecrement(ext);
#endif

error_1:
    PoStartNextPowerIrp(irp);
    irp->IoStatus.Status = status;
    IoCompleteRequest (irp, IO_NO_INCREMENT);
    return status;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, VDIPortSystemControl)
#endif
NTSTATUS VDIPortSystemControl(IN PDEVICE_OBJECT device, IN PIRP irp)
{
    PIO_STACK_LOCATION stack;
    VDIPortExt *ext;
    NTSTATUS status;

    PAGED_CODE();

    DEBUG_PRINT((3, "%s: start\n", __FUNCTION__));

    stack = IoGetCurrentIrpStackLocation(irp);
    ext = device->DeviceExtension;

    status = IoIncrement(ext);
    if (!NT_SUCCESS(status)) {
        DEBUG_PRINT((0, "%s: io increment failed\n", __FUNCTION__));
        goto error_1;
    }

#ifndef USE_REMOVE_LOCK
    if (ext->pnp_state == REMOVED) {
        status = STATUS_NO_SUCH_DEVICE ;
        DEBUG_PRINT((0, "%s: REMOVED\n", __FUNCTION__));
        goto error_2;
    }
#endif
    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(ext->lower_dev, irp);
    DEBUG_PRINT((4, "%s: done\n", __FUNCTION__));
    IoDecrement(ext);
    return status;

#ifndef USE_REMOVE_LOCK
error_2:
    IoDecrement(ext);
#endif

error_1:
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

