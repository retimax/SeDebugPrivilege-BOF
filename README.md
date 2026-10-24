# SeDebugPrivilege-BOF

Beacon Object File that enables `SeDebugPrivilege` on the current process token
and performs classic shellcode injection into a target process via its PID.

Designed for use with **AdaptixC2** through the included `.axs` script.

> **Not OpSec safe by default.** See the OpSec section below.

---

## How it works

1. Calls `OpenProcessToken` + `LookupPrivilegeValueA` + `AdjustTokenPrivileges`
   to enable `SeDebugPrivilege` on the current process — allowing handle
   acquisition against privileged targets.
2. Opens a handle to the target process via `OpenProcess(PROCESS_ALL_ACCESS)`.
3. Allocates a `PAGE_READWRITE` region in the target process with `VirtualAllocEx`.
4. Writes the shellcode with `WriteProcessMemory`.
5. Changes memory permissions to `PAGE_EXECUTE` via `VirtualProtectEx`.
6. Spawns the shellcode with `CreateRemoteThread`.

---

## Usage

### Build

```bash
make
```

### AdaptixC2

Load `SeDebugPrivilege.axs` into the AxScript Manager, then from the agent console:
```shell
sedebug_inject -p <PID> -f <path/to/payload.bin>
```
**Arguments:**

| Flag | Type   | Description                  |
|------|--------|------------------------------|
| `-p` | int    | Target process PID           |
| `-f` | string | Path to shellcode `.bin` file |

---

## OpSec

This BOF is **not OpSec safe by default**. OpSec considerations are split
between two layers: what this BOF is responsible for, and what the operator
is responsible for.

### BOF responsibility

The following are vectors this BOF addresses or that will be improved by the developer itself:

- [ ] Replace `PROCESS_ALL_ACCESS` with minimum required access rights per API call
- [ ] Check token state with `GetTokenInformation` before calling `AdjustTokenPrivileges`
- [x] Add `CloseHandle` on `hToken` after `AdjustTokenPrivileges`
- [ ] Deliver shellcode encrypted — decrypt in-memory before passing to the BOF

### Operator responsibility

The following evasion concerns are **intentionally not addressed at the BOF
level**. A BOF operates inside an already-running agent — the evasion layer
belongs to the tradecraft wrapping it, not the BOF itself:

- **Userland hooks / syscall-level evasion** — direct or indirect syscalls,
  and syscall gates (e.g., HellsGate, TartarusGate) should be implemented
  at the agent or PICO layer, not inside a BOF. A PICO crafted with a
  framework like Crystal Palace, including call stack spoofing and a syscall
  gate, provides this transparently to any BOF running under it.
- **Call stack spoofing** — masking the call chain back to a BOF entry point
  is a concern for the execution wrapper, not the BOF logic.
- **Shellcode source and encryption** — the operator is responsible for
  ensuring the payload delivered via `-f` is appropriately staged, encrypted,
  or obfuscated before transmission.

The correct mental model is: **this BOF provides the capability, the operator
provides the tradecraft**. Conflating both into a single BOF produces a
monolithic tool that is harder to maintain, harder to adapt, and couples
evasion to functionality unnecessarily.