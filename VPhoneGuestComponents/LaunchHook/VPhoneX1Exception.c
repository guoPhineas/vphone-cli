#include "VPhoneX1Exception.h"
#include "VPhoneX1Lowering.h"
#include "VPhoneCSSCEmulation.h"
#include "mach_exc.h"
#include "mach_excServer.h"

#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach/arm/thread_status.h>
#include <mach/host_special_ports.h>
#include <mach/mach.h>
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ptrauth.h>

extern const struct mach_header *_NSGetMachExecuteHeader(void);

static mach_port_t vp_original_exception_port = MACH_PORT_NULL;
static mach_port_t vp_exception_port = MACH_PORT_NULL;
static sigjmp_buf vp_probe_jump;

__attribute__((naked, noinline, used))
static void vp_probe_pauth_lr(void) {
    // Preserve LR because the probe has no matching X1 authentication.
    __asm__ volatile(
        "mov x9, x30\n"
        ".long 0xDAC1A7FE\n" // PACIBSPPC
        "mov x30, x9\n"
        "ret\n"
    );
}

__attribute__((naked, noinline, used))
static uintptr_t vp_probe_cpa(uintptr_t unused, uintptr_t base,
    uintptr_t offset) {
    __asm__ volatile(
        ".long 0x9A022020\n" // ADDPT x0, x1, x2
        "ret\n"
    );
}

__attribute__((naked, noinline, used))
static void vp_probe_cssc(void) {
    __asm__ volatile(
        "mov x0, #0\n"
        ".long 0xDAC01800\n" // CTZ x0, x0
        "ret\n"
    );
}

typedef struct {
    bool task_suspended;
    thread_act_array_t threads;
    mach_msg_type_number_t count;
    unsigned char *suspended;
} VPStoppedTarget;

static bool vp_suspend_target(mach_port_t task, mach_port_t faulting_thread,
    VPStoppedTarget *stopped) {
    memset(stopped, 0, sizeof(*stopped));

    // task_suspend closes the thread-creation race while execute is removed.
    if (task != mach_task_self()) {
        if (task_suspend(task) != KERN_SUCCESS) return false;
        stopped->task_suspended = true;
        return true;
    }

    // launchd cannot task_suspend itself while serving the exception.
    if (task_threads(task, &stopped->threads, &stopped->count) != KERN_SUCCESS)
        return false;
    stopped->suspended = calloc(stopped->count, sizeof(*stopped->suspended));
    if (stopped->suspended == NULL) return false;

    mach_port_t server_thread = mach_thread_self();
    bool complete = true;
    for (mach_msg_type_number_t index = 0; index < stopped->count; index++) {
        mach_port_t candidate = stopped->threads[index];
        if (candidate == faulting_thread || candidate == server_thread) continue;
        if (thread_suspend(candidate) == KERN_SUCCESS)
            stopped->suspended[index] = 1;
        else
            complete = false;
    }
    mach_port_deallocate(mach_task_self(), server_thread);
    return complete;
}

static void vp_resume_target(mach_port_t task, VPStoppedTarget *stopped) {
    if (stopped->task_suspended) (void)task_resume(task);
    if (stopped->threads != NULL) {
        for (mach_msg_type_number_t index = 0; index < stopped->count; index++) {
            if (stopped->suspended != NULL && stopped->suspended[index])
                thread_resume(stopped->threads[index]);
            mach_port_deallocate(mach_task_self(), stopped->threads[index]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)stopped->threads,
            stopped->count * sizeof(*stopped->threads));
    }
    free(stopped->suspended);
    memset(stopped, 0, sizeof(*stopped));
}

static bool vp_is_x1_launchd(void) {
    const struct mach_header *header = _NSGetMachExecuteHeader();
    uint32_t subtype = (uint32_t)header->cpusubtype & ~CPU_SUBTYPE_MASK;
    return header->cputype == CPU_TYPE_ARM64 && subtype == 12;
}

static void *vp_cssc_state_pointer(uintptr_t value) {
#if __has_feature(ptrauth_calls)
    return ptrauth_sign_unauthenticated((void *)value, ptrauth_key_function_pointer, 0);
#else
    return (void *)value;
#endif
}

static bool vp_patch_fault(mach_port_t thread, mach_port_t task,
    const mach_exception_data_t code, mach_msg_type_number_t code_count) {
    if (code_count != 2) return false;

    arm_thread_state64_t state;
    mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state,
            &state_count) != KERN_SUCCESS) return false;
    arm_thread_state64_t updated = state;
    // The remote thread owns the PC signature; inspect a stripped copy.
    arm_thread_state64_ptrauth_strip(state);
    vm_address_t pc = (vm_address_t)arm_thread_state64_get_pc(state);
    if ((pc & 3) != 0) return false;

    uint32_t fault_word = (uint32_t)code[1];
    uint64_t registers[31];
    for (unsigned index = 0; index < 29; index++) registers[index] = state.__x[index];
    registers[29] = arm_thread_state64_get_fp(state);
    registers[30] = arm_thread_state64_get_lr(state);
    if (vp_cssc_emulate(fault_word, registers)) {
        uint32_t current = 0;
        vm_size_t read = 0;
        if (vm_read_overwrite(task, pc, sizeof(current), (vm_address_t)&current, &read) != KERN_SUCCESS ||
            read != sizeof(current) || current != fault_word) return false;
        unsigned rd = fault_word & 31;
        if (rd < 29) updated.__x[rd] = registers[rd];
        else if (rd == 29) {
            arm_thread_state64_set_fp(updated, registers[rd]);
            if (arm_thread_state64_get_fp(updated) != registers[rd]) return false;
        } else if (rd == 30) {
            arm_thread_state64_set_lr_fptr(updated, vp_cssc_state_pointer(registers[rd]));
            if (arm_thread_state64_get_lr(updated) != registers[rd]) return false;
        }
        // Preserve the authenticated state of all untouched pointer fields.
        // NO_PTRAUTH state is refused by a JOP-enabled destination. The SDK
        // setter signs the new PC with its recorded user diversifier instead.
        arm_thread_state64_set_pc_fptr(updated, vp_cssc_state_pointer(pc + 4));
        return thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&updated,
            ARM_THREAD_STATE64_COUNT) == KERN_SUCCESS;
    }
    uint32_t replacement;
    if (!vp_x1_lower_instruction(fault_word, &replacement)) return false;

    uint32_t current = 0;
    vm_size_t read = 0;
    kern_return_t result = vm_read_overwrite(task, pc, sizeof(current),
        (vm_address_t)&current, &read);
    if (result != KERN_SUCCESS || read != sizeof(current) ||
        (current != fault_word && current != replacement)) {
        return false;
    }
    if (current == replacement) {
        return true;
    }

    // Stop peer threads while the private page is writable and non-executable.
    VPStoppedTarget stopped;
    if (!vp_suspend_target(task, thread, &stopped)) {
        vp_resume_target(task, &stopped);
        return false;
    }
    vm_size_t page_size = vm_page_size;
    vm_address_t page = pc & ~(page_size - 1);
    result = vm_protect(task, page, page_size, false,
        VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
    if (result == KERN_SUCCESS) {
        result = vm_write(task, pc, (vm_offset_t)&replacement,
            (mach_msg_type_number_t)sizeof(replacement));
    }
    kern_return_t protected = vm_protect(task, page, page_size, false,
        VM_PROT_READ | VM_PROT_EXECUTE);
    if (result == KERN_SUCCESS && protected == KERN_SUCCESS) {
        vm_machine_attribute_val_t cache = MATTR_VAL_CACHE_FLUSH;
        result = vm_machine_attribute(task, page, page_size, MATTR_CACHE, &cache);
    } else if (result == KERN_SUCCESS) {
        result = protected;
    }
    vp_resume_target(task, &stopped);
    return result == KERN_SUCCESS;
}

static kern_return_t vp_forward(mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t code_count) {
    if (vp_original_exception_port == MACH_PORT_NULL) return KERN_FAILURE;
    return mach_exception_raise(vp_original_exception_port, thread, task,
        exception, code, code_count);
}

kern_return_t catch_mach_exception_raise(mach_port_t port, mach_port_t thread,
    mach_port_t task, exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t code_count) {
    (void)port;
    kern_return_t result = KERN_FAILURE;
    if (exception == EXC_BAD_INSTRUCTION &&
        vp_patch_fault(thread, task, code, code_count)) {
        result = KERN_SUCCESS;
    } else {
        result = vp_forward(thread, task, exception, code, code_count);
    }
    // mach_msg_server destroys moved rights only when the callback fails.
    if (result == KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), thread);
        mach_port_deallocate(mach_task_self(), task);
    }
    return result;
}

kern_return_t catch_mach_exception_raise_state(mach_port_t port,
    exception_type_t exception, const mach_exception_data_t code,
    mach_msg_type_number_t code_count, int *flavor,
    const thread_state_t old_state, mach_msg_type_number_t old_count,
    thread_state_t new_state, mach_msg_type_number_t *new_count) {
    (void)port; (void)exception; (void)code; (void)code_count; (void)flavor;
    (void)old_state; (void)old_count; (void)new_state; (void)new_count;
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(mach_port_t port,
    mach_port_t thread, mach_port_t task, exception_type_t exception,
    mach_exception_data_t code, mach_msg_type_number_t code_count, int *flavor,
    thread_state_t old_state, mach_msg_type_number_t old_count,
    thread_state_t new_state, mach_msg_type_number_t *new_count) {
    (void)port; (void)thread; (void)task; (void)exception; (void)code;
    (void)code_count; (void)flavor; (void)old_state; (void)old_count;
    (void)new_state; (void)new_count;
    return KERN_FAILURE;
}

static void *vp_exception_server(void *opaque) {
    mach_port_t port = (mach_port_t)(uintptr_t)opaque;
    (void)mach_msg_server(mach_exc_server, 8192, port, 0);
    return NULL;
}

static void vp_probe_sigill(int signal) {
    (void)signal;
    siglongjmp(vp_probe_jump, 1);
}

static bool vp_probe_native_x1(void) {
    // Probe in a child; any setup or wait failure selects compatibility.
    int result_pipe[2];
    if (pipe(result_pipe) != 0) return false;
    pid_t child = fork();
    if (child < 0) {
        close(result_pipe[0]);
        close(result_pipe[1]);
        return false;
    }
    if (child == 0) {
        close(result_pipe[0]);
        struct sigaction action = {0};
        action.sa_handler = vp_probe_sigill;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGILL, &action, NULL) != 0) _exit(2);
        int trapped = sigsetjmp(vp_probe_jump, 1);
        unsigned char supported = 0;
        if (trapped == 0) {
            uintptr_t marker = 0;
            vp_probe_pauth_lr();
            (void)vp_probe_cpa(0, (uintptr_t)&marker, 0);
            vp_probe_cssc();
            supported = 1;
        }
        (void)write(result_pipe[1], &supported, sizeof(supported));
        _exit(supported ? 0 : 1);
    }

    close(result_pipe[1]);
    unsigned char supported = 0;
    ssize_t bytes;
    do {
        bytes = read(result_pipe[0], &supported, sizeof(supported));
    } while (bytes < 0 && errno == EINTR);
    close(result_pipe[0]);

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    bool reaped = waited == child || (waited < 0 && errno == ECHILD);
    return bytes == sizeof(supported) && supported == 1 && reaped;
}

static void vp_dispose_exception_service(void) {
    mach_port_t port = vp_exception_port;
    vp_exception_port = MACH_PORT_NULL;
    if (port != MACH_PORT_NULL) {
        // Allocation and send-right insertion can fail independently.
        (void)mach_port_mod_refs(
            mach_task_self(), port, MACH_PORT_RIGHT_SEND, -1);
        (void)mach_port_mod_refs(
            mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
    }
    if (vp_original_exception_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), vp_original_exception_port);
        vp_original_exception_port = MACH_PORT_NULL;
    }
}

void vp_x1_exception_install(void) {
    if (getpid() != 1 || !vp_is_x1_launchd()) return;
    if (vp_probe_native_x1()) return;

    mach_port_t host = mach_host_self();
    mach_port_t privileged = MACH_PORT_NULL;
    if (host_get_special_port(host, HOST_LOCAL_NODE, HOST_PRIV_PORT,
            &privileged) != KERN_SUCCESS) return;

    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    kern_return_t result = host_get_exception_ports(privileged,
        EXC_MASK_BAD_INSTRUCTION, masks, &count, ports, behaviors, flavors);
    if (result != KERN_SUCCESS || count != 1 ||
        (masks[0] & EXC_MASK_BAD_INSTRUCTION) == 0 ||
        behaviors[0] != (exception_behavior_t)(
            EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES)) {
        if (result == KERN_SUCCESS) {
            for (mach_msg_type_number_t i = 0; i < count; i++) {
                if (ports[i] != MACH_PORT_NULL)
                    mach_port_deallocate(mach_task_self(), ports[i]);
            }
        }
        mach_port_deallocate(mach_task_self(), privileged);
        mach_port_deallocate(mach_task_self(), host);
        return;
    }

    vp_original_exception_port = ports[0];
    result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
        &vp_exception_port);
    if (result == KERN_SUCCESS) {
        result = mach_port_insert_right(mach_task_self(), vp_exception_port,
            vp_exception_port, MACH_MSG_TYPE_MAKE_SEND);
    }
    pthread_t server;
    if (result == KERN_SUCCESS) {
        result = pthread_create(&server, NULL, vp_exception_server,
            (void *)(uintptr_t)vp_exception_port);
        if (result == 0) {
            pthread_detach(server);
        }
    }
    if (result == KERN_SUCCESS) {
        // Spawn hooks propagate this action; unsupported faults are forwarded.
        result = task_set_exception_ports(
            mach_task_self(),
            EXC_MASK_BAD_INSTRUCTION,
            vp_exception_port,
            EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
            0
        );
    }
    if (result != KERN_SUCCESS) vp_dispose_exception_service();
    mach_port_deallocate(mach_task_self(), privileged);
    mach_port_deallocate(mach_task_self(), host);
}
