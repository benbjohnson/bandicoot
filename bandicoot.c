#define _XOPEN_SOURCE 700

#include <signal.h>
#include <execinfo.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <ucontext.h>

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#endif

#include "bandicoot.h"

//==============================================================================
//
// Forward Declarations
//
//==============================================================================

void bandicoot_sigsegv(int sig, siginfo_t *info, void *_uap);

void bandicoot_print_backtrace(ucontext_t *uap);

void *bandicoot_mcontext_eip(ucontext_t *uap);

void bandicoot_print_stack(void **sp);

void bandicoot_print_registers(ucontext_t *uap);

void bandicoot_kill(int sig);


//==============================================================================
//
// Functions
//
//==============================================================================

//--------------------------------------
// Initialization
//--------------------------------------

// Initializes bandicoot bug reporting on segfault.
void bandicoot_init()
{
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
    act.sa_sigaction = bandicoot_sigsegv;
    sigaction(SIGSEGV, &act, 0);
    sigaction(SIGBUS, &act, 0);
    sigaction(SIGFPE, &act, 0);
    sigaction(SIGILL, &act, 0);
}


//--------------------------------------
// Signal Handlers
//--------------------------------------

// This function is called when a segmentation fault occurs.
//
// sig  - The signal being handled.
// info - Unused.
// uap  - The user thread context.
//
// Returns NULL.
void bandicoot_sigsegv(int sig, siginfo_t *info, void *_uap) {
    ucontext_t *uap = (ucontext_t*)_uap;
    ((void) info);

    // Print header.
    fprintf(stderr, "\n\n");
    fprintf(stderr, "=== BUG REPORT [BEGIN] ===\n");
    fprintf(stderr, "SIGNAL: %d\n", sig);
    fprintf(stderr, "\n");

    // Print stack trace.
    fprintf(stderr, "--- STACK TRACE ---\n");
    bandicoot_print_backtrace(uap);
    fprintf(stderr, "\n");

    // Print registers.
    fprintf(stderr, "--- REGISTERS ---\n");
    bandicoot_print_registers(uap);
    fprintf(stderr, "\n");

    // Print footer.
    fprintf(stderr, "=== BUG REPORT [END] ===\n\n");

    // Defer kill to normal signal handler.
    bandicoot_kill(sig);
}


//--------------------------------------
// Backtrace
//--------------------------------------

// Prints the backtrace for a given user thread context to STDERR.
//
// uap - The user thread context.
void bandicoot_print_backtrace(ucontext_t *uap)
{
    void *trace[100];
    int sz = backtrace(trace, 100);
    if(bandicoot_mcontext_eip(uap) != 0) trace[1] = bandicoot_mcontext_eip(uap);
    backtrace_symbols_fd(trace, sz, STDERR_FILENO);
}

void *bandicoot_mcontext_eip(ucontext_t *uap) {
#if defined(__APPLE__) && !defined(MAC_OS_X_VERSION_10_6)
    /* OSX < 10.6 */
    #if defined(__x86_64__)
    return (void*) uap->uc_mcontext->__ss.__rip;
    #elif defined(__i386__)
    return (void*) uap->uc_mcontext->__ss.__eip;
    #else
    return (void*) uap->uc_mcontext->__ss.__srr0;
    #endif
#elif defined(__APPLE__) && defined(MAC_OS_X_VERSION_10_6)
    /* OSX >= 10.6 */
    #if defined(_STRUCT_X86_THREAD_STATE64) && !defined(__i386__)
    return (void*) uap->uc_mcontext->__ss.__rip;
    #else
    return (void*) uap->uc_mcontext->__ss.__eip;
    #endif
#elif defined(__linux__)
    /* Linux */
    #if defined(__i386__)
    return (void*) uap->uc_mcontext.gregs[14]; /* Linux 32 */
    #elif defined(__X86_64__) || defined(__x86_64__)
    return (void*) uap->uc_mcontext.gregs[16]; /* Linux 64 */
    #elif defined(__ia64__) /* Linux IA64 */
    return (void*) uap->uc_mcontext.sc_ip;
    #endif
#else
    return 0;
#endif
}


//--------------------------------------
// Registers
//--------------------------------------

// Prints the contents of all registers to STDERR.
//
// uap - The user thread context.
void bandicoot_print_registers(ucontext_t *uap)
{
/* OSX */
#if defined(__APPLE__) && defined(MAC_OS_X_VERSION_10_6)
  /* OSX AMD64 */
    #if defined(_STRUCT_X86_THREAD_STATE64) && !defined(__i386__)
    fprintf(stderr,
    "RAX:%016llx RBX:%016llx\n"
    "RCX:%016llx RDX:%016llx\n"
    "RDI:%016llx RSI:%016llx\n"
    "RBP:%016llx RSP:%016llx\n"
    "R8 :%016llx R9 :%016llx\n"
    "R10:%016llx R11:%016llx\n"
    "R12:%016llx R13:%016llx\n"
    "R14:%016llx R15:%016llx\n"
    "RIP:%016llx EFL:%016llx\n"
    "CS :%016llx FS :%016llx\n"
    "GS :%016llx\n\n",
        uap->uc_mcontext->__ss.__rax,
        uap->uc_mcontext->__ss.__rbx,
        uap->uc_mcontext->__ss.__rcx,
        uap->uc_mcontext->__ss.__rdx,
        uap->uc_mcontext->__ss.__rdi,
        uap->uc_mcontext->__ss.__rsi,
        uap->uc_mcontext->__ss.__rbp,
        uap->uc_mcontext->__ss.__rsp,
        uap->uc_mcontext->__ss.__r8,
        uap->uc_mcontext->__ss.__r9,
        uap->uc_mcontext->__ss.__r10,
        uap->uc_mcontext->__ss.__r11,
        uap->uc_mcontext->__ss.__r12,
        uap->uc_mcontext->__ss.__r13,
        uap->uc_mcontext->__ss.__r14,
        uap->uc_mcontext->__ss.__r15,
        uap->uc_mcontext->__ss.__rip,
        uap->uc_mcontext->__ss.__rflags,
        uap->uc_mcontext->__ss.__cs,
        uap->uc_mcontext->__ss.__fs,
        uap->uc_mcontext->__ss.__gs
    );
    bandicoot_print_stack((void**)uap->uc_mcontext->__ss.__rsp);
    #else
    /* OSX x86 */
    fprintf(stderr,
    "EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n"
    "EDI:%08lx ESI:%08lx EBP:%08lx ESP:%08lx\n"
    "SS:%08lx  EFL:%08lx EIP:%08lx CS :%08lx\n"
    "DS:%08lx  ES:%08lx  FS :%08lx GS :%08lx\n\n",
        uap->uc_mcontext->__ss.__eax,
        uap->uc_mcontext->__ss.__ebx,
        uap->uc_mcontext->__ss.__ecx,
        uap->uc_mcontext->__ss.__edx,
        uap->uc_mcontext->__ss.__edi,
        uap->uc_mcontext->__ss.__esi,
        uap->uc_mcontext->__ss.__ebp,
        uap->uc_mcontext->__ss.__esp,
        uap->uc_mcontext->__ss.__ss,
        uap->uc_mcontext->__ss.__eflags,
        uap->uc_mcontext->__ss.__eip,
        uap->uc_mcontext->__ss.__cs,
        uap->uc_mcontext->__ss.__ds,
        uap->uc_mcontext->__ss.__es,
        uap->uc_mcontext->__ss.__fs,
        uap->uc_mcontext->__ss.__gs
    );
    bandicoot_print_stack((void**)uap->uc_mcontext->__ss.__esp);
    #endif
/* Linux */
#elif defined(__linux__)
    /* Linux x86 */
    #if defined(__i386__)
    fprintf(stderr,
    "EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n"
    "EDI:%08lx ESI:%08lx EBP:%08lx ESP:%08lx\n"
    "SS :%08lx EFL:%08lx EIP:%08lx CS:%08lx\n"
    "DS :%08lx ES :%08lx FS :%08lx GS:%08lx\n\n",
        uap->uc_mcontext.gregs[11],
        uap->uc_mcontext.gregs[8],
        uap->uc_mcontext.gregs[10],
        uap->uc_mcontext.gregs[9],
        uap->uc_mcontext.gregs[4],
        uap->uc_mcontext.gregs[5],
        uap->uc_mcontext.gregs[6],
        uap->uc_mcontext.gregs[7],
        uap->uc_mcontext.gregs[18],
        uap->uc_mcontext.gregs[17],
        uap->uc_mcontext.gregs[14],
        uap->uc_mcontext.gregs[15],
        uap->uc_mcontext.gregs[3],
        uap->uc_mcontext.gregs[2],
        uap->uc_mcontext.gregs[1],
        uap->uc_mcontext.gregs[0]
    );
    bandicoot_print_stack((void**)uap->uc_mcontext.gregs[7]);
    #elif defined(__X86_64__) || defined(__x86_64__)
    /* Linux AMD64 */
    fprintf(stderr,
    "RAX:%016lx RBX:%016lx\n"
    "RCX:%016lx RDX:%016lx\n"
    "RDI:%016lx RSI:%016lx\n"
    "RBP:%016lx RSP:%016lx\n"
    "R8 :%016lx R9 :%016lx\n"
    "R10:%016lx R11:%016lx\n"
    "R12:%016lx R13:%016lx\n"
    "R14:%016lx R15:%016lx\n"
    "RIP:%016lx EFL:%016lx\n"
    "CSGSFS:%016lx\n\n",
        uap->uc_mcontext.gregs[13],
        uap->uc_mcontext.gregs[11],
        uap->uc_mcontext.gregs[14],
        uap->uc_mcontext.gregs[12],
        uap->uc_mcontext.gregs[8],
        uap->uc_mcontext.gregs[9],
        uap->uc_mcontext.gregs[10],
        uap->uc_mcontext.gregs[15],
        uap->uc_mcontext.gregs[0],
        uap->uc_mcontext.gregs[1],
        uap->uc_mcontext.gregs[2],
        uap->uc_mcontext.gregs[3],
        uap->uc_mcontext.gregs[4],
        uap->uc_mcontext.gregs[5],
        uap->uc_mcontext.gregs[6],
        uap->uc_mcontext.gregs[7],
        uap->uc_mcontext.gregs[16],
        uap->uc_mcontext.gregs[17],
        uap->uc_mcontext.gregs[18]
    );
    bandicoot_print_stack((void**)uap->uc_mcontext.gregs[15]);
    #endif
#else
fprintf(stderr, "<unavailable>\n");
#endif
}

// Prints the contents of the stack.
//
// ptr - A poiner to the stack.
void bandicoot_print_stack(void **ptr) {
    fprintf(stderr, "--- STACK VARIABLES ---\n");
    int i;
    for(i = 15; i >= 0; i--) {
        if (sizeof(long) == 4) {
            fprintf(stderr, "(%08lx) -> %08lx\n", (unsigned long)(ptr+i), (unsigned long)ptr[i]);
        }
        else {
            fprintf(stderr, "(%016lx) -> %016lx\n", (unsigned long)(ptr+i), (unsigned long)ptr[i]);
        }
    }
}


//--------------------------------------
// Kill
//--------------------------------------

// Changes the signal handler to the default handler and reissues the signal.
//
// sig - The signal to send.
void bandicoot_kill(int sig)
{
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_ONSTACK | SA_RESETHAND;
    act.sa_handler = SIG_DFL;
    sigaction(sig, &act, 0);
    kill(getpid(),sig);
}

