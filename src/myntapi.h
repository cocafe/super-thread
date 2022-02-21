#ifndef SUPER_THREAD_MYNTAPI_H
#define SUPER_THREAD_MYNTAPI_H

// some structs are taken from process hacker

#include <winternl.h>

typedef enum _PH_THREADINFOCLASS
{
        PhThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
        PhThreadTimes, // q: KERNEL_USER_TIMES
        PhThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
        PhThreadBasePriority, // s: LONG
        PhThreadAffinityMask, // s: KAFFINITY
        PhThreadImpersonationToken, // s: HANDLE
        PhThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
        PhThreadEnableAlignmentFaultFixup, // s: BOOLEAN
        PhThreadEventPair,
        PhThreadQuerySetWin32StartAddress, // q: ULONG_PTR
        PhThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
        PhThreadPerformanceCount, // q: LARGE_INTEGER
        PhThreadAmILastThread, // q: ULONG
        PhThreadIdealProcessor, // s: ULONG
        PhThreadPriorityBoost, // qs: ULONG
        PhThreadSetTlsArrayAddress, // s: ULONG_PTR
        PhThreadIsIoPending, // q: ULONG
        PhThreadHideFromDebugger, // q: BOOLEAN; s: void
        PhThreadBreakOnTermination, // qs: ULONG
        PhThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
        PhThreadIsTerminated, // q: ULONG // 20
        PhThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
        PhThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
        PhThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
        PhThreadPagePriority, // q: ULONG
        PhThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
        PhThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
        PhThreadCSwitchMon,
        PhThreadCSwitchPmu,
        PhThreadWow64Context, // qs: WOW64_CONTEXT
        PhThreadGroupInformation, // q: GROUP_AFFINITY // 30
        PhThreadUmsInformation, // q: THREAD_UMS_INFORMATION
        PhThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
        PhThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
        PhThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
        PhThreadSuspendCount, // q: ULONG // since WINBLUE
        PhThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
        PhThreadContainerId, // q: GUID
        PhThreadNameInformation, // qs: THREAD_NAME_INFORMATION
        PhThreadSelectedCpuSets,
        PhThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
        PhThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
        PhThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
        PhThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
        PhThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
        PhThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        PhThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
        PhThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
        PhThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        PhThreadPowerThrottlingState, // POWER_THROTTLING_THREAD_STATE
        PhThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
        PhThreadCreateStateChange, // since WIN11
        PhThreadApplyStateChange,
        PhMaxThreadInfoClass
} PH_THREADINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION
{
        NTSTATUS ExitStatus;
        PTEB TebBaseAddress;
        CLIENT_ID ClientId;
        ULONG_PTR AffinityMask;
        KPRIORITY Priority;
        LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// Use with both ProcessPagePriority and ThreadPagePriority
typedef struct _PAGE_PRIORITY_INFORMATION
{
        ULONG PagePriority;
} PAGE_PRIORITY_INFORMATION, *PPAGE_PRIORITY_INFORMATION;

#define MEMORY_PRIORITY_LOWEST          0
//#define MEMORY_PRIORITY_VERY_LOW        1
//#define MEMORY_PRIORITY_LOW             2
//#define MEMORY_PRIORITY_MEDIUM          3
//#define MEMORY_PRIORITY_BELOW_NORMAL    4
//#define MEMORY_PRIORITY_NORMAL          5
//
//#define THREAD_BASE_PRIORITY_LOWRT      15      // value that gets a thread to LowRealtime-1
//#define THREAD_BASE_PRIORITY_MAX        2       // maximum thread base priority boost
//#define THREAD_BASE_PRIORITY_MIN        (-2)    // minimum thread base priority boost
//#define THREAD_BASE_PRIORITY_IDLE       (-15)   // value that gets a thread to idle
//
//#define THREAD_PRIORITY_LOWEST          THREAD_BASE_PRIORITY_MIN
//#define THREAD_PRIORITY_BELOW_NORMAL    (THREAD_PRIORITY_LOWEST+1)
//#define THREAD_PRIORITY_NORMAL          0
//#define THREAD_PRIORITY_HIGHEST         THREAD_BASE_PRIORITY_MAX
//#define THREAD_PRIORITY_ABOVE_NORMAL    (THREAD_PRIORITY_HIGHEST-1)
//#define THREAD_PRIORITY_ERROR_RETURN    (MAXLONG)
//
//#define THREAD_PRIORITY_TIME_CRITICAL   THREAD_BASE_PRIORITY_LOWRT
//#define THREAD_PRIORITY_IDLE            THREAD_BASE_PRIORITY_IDLE

typedef enum _PROC_PRIORITY_HINT {
        ProcPrioClassUnknown             = 0,
        ProcPrioClassIdle,              // 1
        ProcPrioClassNormal,            // 2
        ProcPrioClassHigh,              // 3
        ProcPrioClassRealtime,          // 4
        ProcPrioClassBelowNormal,       // 5
        ProcPrioClassAboveNormal,       // 6
        MaxProcPrioClasses,
} PROC_PRIORITY_HINT;

typedef struct _PROCESS_PRIORITY_CLASS
{
        BOOLEAN Foreground;
        UCHAR PriorityClass; // PROC_PRIORITY_HINT
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

typedef struct _PROCESS_FOREGROUND_BACKGROUND
{
        BOOLEAN Foreground;
} PROCESS_FOREGROUND_BACKGROUND, *PPROCESS_FOREGROUND_BACKGROUND;

typedef enum _IO_PRIORITY_HINT
{
        IoPriorityVeryLow = 0,  // Defragging, content indexing and other background I/Os.
        IoPriorityLow,          // Prefetching for applications.
        IoPriorityNormal,       // Normal I/Os.
        IoPriorityHigh,         // Used by filesystems for checkpoint I/O.
        IoPriorityCritical,     // Used by memory manager. Not available for applications.
        MaxIoPriorityTypes
} IO_PRIORITY_HINT;

NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationThread(_In_ HANDLE ThreadHandle,
                                                   _In_ THREADINFOCLASS ThreadInformationClass,
                                                   _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
                                                   _In_ ULONG ThreadInformationLength);

FORCEINLINE
NTSTATUS
PhGetProcessPagePriority(
        _In_ HANDLE ProcessHandle,
        _Out_ PULONG PagePriority
                        )
{
        NTSTATUS status;
        PAGE_PRIORITY_INFORMATION pagePriorityInfo;

        status = NtQueryInformationProcess(
                ProcessHandle,
                ProcessPagePriority,
                &pagePriorityInfo,
                sizeof(PAGE_PRIORITY_INFORMATION),
                NULL
                                          );

        if (NT_SUCCESS(status))
        {
                *PagePriority = pagePriorityInfo.PagePriority;
        }

        return status;
}

FORCEINLINE
NTSTATUS
PhSetProcessPagePriority(
        _In_ HANDLE ProcessHandle,
        _In_ ULONG PagePriority
                        )
{
        PAGE_PRIORITY_INFORMATION pagePriorityInfo;

        pagePriorityInfo.PagePriority = PagePriority;

        return NtSetInformationProcess(
                ProcessHandle,
                ProcessPagePriority,
                &pagePriorityInfo,
                sizeof(PAGE_PRIORITY_INFORMATION)
                                      );
}

FORCEINLINE
NTSTATUS
PhGetProcessPriorityBoost(
        _In_ HANDLE ProcessHandle,
        _Out_ PBOOLEAN PriorityBoost
                         )
{
        NTSTATUS status;
        ULONG priorityBoost;

        status = NtQueryInformationProcess(
                ProcessHandle,
                ProcessPriorityBoost,
                &priorityBoost,
                sizeof(ULONG),
                NULL
                                          );

        if (NT_SUCCESS(status))
        {
                *PriorityBoost = !!priorityBoost;
        }

        return status;
}

FORCEINLINE
NTSTATUS
PhSetProcessPriorityBoost(
        _In_ HANDLE ProcessHandle,
        _In_ BOOLEAN PriorityBoost
                         )
{
        ULONG priorityBoost;

        priorityBoost = PriorityBoost ? 1 : 0;

        return NtSetInformationProcess(
                ProcessHandle,
                ProcessPriorityBoost,
                &priorityBoost,
                sizeof(ULONG)
                                      );
}

FORCEINLINE
NTSTATUS
PhGetThreadPagePriority(
        _In_ HANDLE ThreadHandle,
        _Out_ PULONG PagePriority
                       )
{
        NTSTATUS status;
        PAGE_PRIORITY_INFORMATION pagePriorityInfo;

        status = NtQueryInformationThread(
                ThreadHandle,
                (THREADINFOCLASS)PhThreadPagePriority,
                &pagePriorityInfo,
                sizeof(PAGE_PRIORITY_INFORMATION),
                NULL
                                         );

        if (NT_SUCCESS(status))
        {
                *PagePriority = pagePriorityInfo.PagePriority;
        }

        return status;
}

FORCEINLINE
NTSTATUS
PhSetThreadPagePriority(
        _In_ HANDLE ThreadHandle,
        _In_ ULONG PagePriority
                       )
{
        PAGE_PRIORITY_INFORMATION pagePriorityInfo;

        pagePriorityInfo.PagePriority = PagePriority;

        return NtSetInformationThread(
                ThreadHandle,
                (THREADINFOCLASS)PhThreadPagePriority,
                &pagePriorityInfo,
                sizeof(PAGE_PRIORITY_INFORMATION)
                                     );
}

FORCEINLINE
NTSTATUS
PhGetThreadPriorityBoost(
        _In_ HANDLE ThreadHandle,
        _Out_ PBOOLEAN PriorityBoost
                        )
{
        NTSTATUS status;
        ULONG priorityBoost;

        status = NtQueryInformationThread(
                ThreadHandle,
                ThreadPriorityBoost,
                &priorityBoost,
                sizeof(ULONG),
                NULL
                                         );

        if (NT_SUCCESS(status))
        {
                *PriorityBoost = !!priorityBoost;
        }

        return status;
}

FORCEINLINE
NTSTATUS
PhSetThreadPriorityBoost(
        _In_ HANDLE ThreadHandle,
        _In_ BOOLEAN PriorityBoost
                        )
{
        ULONG priorityBoost;

        priorityBoost = PriorityBoost ? 1 : 0;

        return NtSetInformationThread(
                ThreadHandle,
                ThreadPriorityBoost,
                &priorityBoost,
                sizeof(ULONG)
                                     );
}

FORCEINLINE
NTSTATUS
PhGetThreadIdealProcessor(
        _In_ HANDLE ThreadHandle,
        _Out_ PPROCESSOR_NUMBER ProcessorNumber
                         )
{
        return NtQueryInformationThread(
                ThreadHandle,
                (THREADINFOCLASS)PhThreadIdealProcessorEx,
                ProcessorNumber,
                sizeof(PROCESSOR_NUMBER),
                NULL
                                       );
}

FORCEINLINE
NTSTATUS
PhGetThreadIsTerminated(
        _In_ HANDLE ThreadHandle,
        _Out_ PBOOLEAN IsTerminated
                       )
{
        NTSTATUS status;
        ULONG threadIsTerminated;

        status = NtQueryInformationThread(
                ThreadHandle,
                (THREADINFOCLASS)PhThreadIsTerminated,
                &threadIsTerminated,
                sizeof(ULONG),
                NULL
                                         );

        if (NT_SUCCESS(status))
        {
                *IsTerminated = !!threadIsTerminated;
        }

        return status;
}

FORCEINLINE
NTSTATUS
PhGetThreadIoPriority(
        _In_ HANDLE ThreadHandle,
        _Out_ IO_PRIORITY_HINT *IoPriority
                     )
{
        return NtQueryInformationThread(
                ThreadHandle,
                (THREADINFOCLASS)PhThreadIoPriority,
                IoPriority,
                sizeof(IO_PRIORITY_HINT),
                NULL
                                       );
}

FORCEINLINE
NTSTATUS
PhSetThreadIoPriority(
        _In_ HANDLE ThreadHandle,
        _In_ IO_PRIORITY_HINT IoPriority
                     )
{
        return NtSetInformationThread(
                ThreadHandle,
                (THREADINFOCLASS)PhThreadIoPriority,
                &IoPriority,
                sizeof(IO_PRIORITY_HINT)
                                     );
}

#endif //SUPER_THREAD_MYNTAPI_H
