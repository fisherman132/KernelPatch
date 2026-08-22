/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_KSH_ROUTE_BROKER_H_
#define _KP_KSH_ROUTE_BROKER_H_

#include <hook.h>
#include <ktypes.h>

#define KP_KSH_ROUTE_BROKER_ABI_VERSION 1u
#define KP_KSH_ROUTE_MEM_ABORT (1u << 0)
#define KP_KSH_ROUTE_EXIT_MMAP (1u << 1)
#define KP_KSH_ROUTE_MUNMAP (1u << 2)
#define KP_KSH_ROUTE_MPROTECT (1u << 3)
#define KP_KSH_ROUTE_COPY_PROCESS (1u << 4)
#define KP_KSH_ROUTE_BEGIN_EXEC (1u << 5)
#define KP_KSH_ROUTE_ALL 0x3fu

struct kp_ksh_route_client {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t route_mask;
    uint32_t reserved;
    hook_chain3_callback mem_abort_before;
    hook_chain1_callback exit_mmap_before;
    hook_chain1_callback exit_mmap_after;
    hook_chain4_callback munmap_5_10_before;
    hook_chain4_callback munmap_5_10_after;
    hook_chain6_callback munmap_6_6_before;
    hook_chain6_callback munmap_6_6_after;
    hook_chain5_callback mprotect_5_10_before;
    hook_chain5_callback mprotect_5_10_after;
    hook_chain7_callback mprotect_6_6_before;
    hook_chain7_callback mprotect_6_6_after;
    hook_chain8_callback copy_process_before;
    hook_chain8_callback copy_process_after;
    hook_chain1_callback begin_exec_before;
    hook_chain1_callback begin_exec_after;
    void *context;
    uint64_t reserved2[2];
};

int kp_ksh_route_broker_init(void);
int kp_ksh_route_broker_register(const struct kp_ksh_route_client *client);
int kp_ksh_route_broker_set_mask(uint32_t mask);
uint32_t kp_ksh_route_installed(void);
uint32_t kp_ksh_route_active(void);

#endif
