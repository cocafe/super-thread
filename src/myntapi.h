#ifndef SUPER_THREAD_MYNTAPI_H
#define SUPER_THREAD_MYNTAPI_H

// some structs are taken from process hacker

enum _PROC_PRIORITY_HINT {
        ProcPrioClassUnknown = 0,
        ProcPrioClassIdle,
        ProcPrioClassNormal,
        ProcPrioClassHigh,
        ProcPrioClassRealtime,
        ProcPrioClassAboveNormal,
        ProcPrioClassBelowNormal,
        MaxProcPrioClasses,
};

typedef struct _PROCESS_PRIORITY_CLASS
{
        BOOLEAN Foreground;
        UCHAR PriorityClass;
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

typedef struct _PROCESS_FOREGROUND_BACKGROUND
{
        BOOLEAN Foreground;
} PROCESS_FOREGROUND_BACKGROUND, *PPROCESS_FOREGROUND_BACKGROUND;

typedef enum _IO_PRIORITY_HINT
{
        IoPriorityVeryLow = 0, // Defragging, content indexing and other background I/Os.
        IoPriorityLow, // Prefetching for applications.
        IoPriorityNormal, // Normal I/Os.
        IoPriorityHigh, // Used by filesystems for checkpoint I/O.
        IoPriorityCritical, // Used by memory manager. Not available for applications.
        MaxIoPriorityTypes
} IO_PRIORITY_HINT;

#endif //SUPER_THREAD_MYNTAPI_H
