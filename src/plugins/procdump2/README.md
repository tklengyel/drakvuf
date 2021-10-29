# Abstract

The _procdump_ plug-in dumps process's virtual memory on process termination.

## Description

The plug-in hooks two system calls:
* `NtTerminateProcess` is used to create new tasks.
* `KiDeliverApc` is used for searching working process.

### `NtTerminateProcess` hook

There are several reasons for hook callback occure:
* The process terminates self.
* The process terminates other.
* The self-terminating process return from injected `PsSuspendProcess`.
* The process evaluates `NtTerminateProcess` several times.

#### Process terminates self

For self-terminating process the new pending task is created and
`PsSuspendProcess` is injected.

#### Process terminates other

If this is the case the new task is created and return from `NtTerminateProcess`
is injected with `STATUS_SUCCESS`. The task requires to suspend target process.

This is done to avoid poluting the callee context with function injection.
Though this is a subject for change.

#### The self-terminating process return from `PsSuspendProcess`

For some reasons the suspended process could wake up:
* `PsResumeProcess` injected on task completion. If this is the case finish the
  task.
* Some system event. If this is the case re-inject `PsSuspendProcess`.

#### `NtTerminatedProcess` been evaluated several times

At least two reasons are known:
* `kernel32!ExitProcess` calls `NtTerminateProcess` two times.
* Some system event. May be OS job object completion.

In both cases return from `NtTerminateProcess` is injected.

### `KiDeliverApc` hook

The hook is used to search for _working thread_ and perform task's operation
with injection chain.

To achive this the task's _stage_ is checked:
* If active task is found and return context matches the current one then
  continue processing.
* Check if current thread is good candidate for task processing and if it is
  then process the task.

#### Checking if thread could be used to process the task

The candidate sould not be attached to other process and should not be
terminated before task completion.

It have been noticed that several system user space processes are good enougth
to be used: _lsass_, _csrss_, _conhost_, _services_, _svchost_. Though there
are no guaranties that this processes would not be terminated.

For good candidate one have to check that it's IRQL is low with
`KeGetCurrentIrql`.

If target process not been suspended one have to inject `PsSuspendProcess`.

## The tasks state machine

```
┌────────────┐     ┌───────┬───────────┐
│need_suspend│ ┌──►│pending│           │
└──────┬─────┘ │   └─┬─────┘           │
       │       │     │   ▲             │
       │       │     │   │             │
       ▼       │     ▼   │             ▼
   ┌───────┐   │   ┌─────┴──┐   ┌─────────────┐
   │suspend├───┘   │get_irql│◄──┤allocate_pool│
   └───────┘       └───┬────┘   └─────────────┘
                       │
                       │
                       ▼
                 ┌───────────┐◄──┐
                 │copy_memory│   │
                 └─────┬─────┴───┘
                       │
                       │
                       ▼
                    ┌──────┐
               ┌────┤resume├─────┐
               │    └──────┘     │
               │                 │
               │                 │
               ▼                 ▼
            ┌──────┐        ┌────────┐
            │awaken│        │finished│
            └──────┘        └────────┘
```

## FAQ

### Why `procdump_fail` occur?

* On buffer allocation error (`ExAllocatePoolWithTag` return `NULL`).
  E.g. many tasks have been queued while waiting for working process.
* On empty process memory map.
  Memory map is constructed based on VAD tree.
