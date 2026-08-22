/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <common.h>
#include <hook.h>
#include <kallsyms.h>
#include <ksh_route_broker.h>
#include <linux/string.h>
#include <symbol.h>
#include <uapi/asm-generic/errno.h>

#define KP_KSH_KVER_ANDROID12_5_10_236 0x050aecu
#define KP_KSH_KVER_ANDROID15_6_6_30 0x06061eu

static struct kp_ksh_route_client route_client;
static uint32_t route_registered;
static uint32_t route_installed_mask;
static uint32_t route_active_mask;

static int route_enabled(uint32_t route)
{
    return __atomic_load_n(&route_registered, __ATOMIC_ACQUIRE) != 0u &&
           (__atomic_load_n(&route_active_mask, __ATOMIC_ACQUIRE) & route) != 0u;
}

static void broker_mem_abort_before(hook_fargs3_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_MEM_ABORT) && route_client.mem_abort_before)
        route_client.mem_abort_before(args, route_client.context);
}

static void broker_exit_mmap_before(hook_fargs1_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_EXIT_MMAP) && route_client.exit_mmap_before)
        route_client.exit_mmap_before(args, route_client.context);
}

static void broker_exit_mmap_after(hook_fargs1_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_EXIT_MMAP) && route_client.exit_mmap_after)
        route_client.exit_mmap_after(args, route_client.context);
}

static void broker_munmap_5_10_before(hook_fargs4_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_MUNMAP) && route_client.munmap_5_10_before)
        route_client.munmap_5_10_before(args, route_client.context);
}

static void broker_munmap_5_10_after(hook_fargs4_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_MUNMAP) && route_client.munmap_5_10_after)
        route_client.munmap_5_10_after(args, route_client.context);
}

static void broker_munmap_6_6_before(hook_fargs6_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_MUNMAP) && route_client.munmap_6_6_before)
        route_client.munmap_6_6_before(args, route_client.context);
}

static void broker_munmap_6_6_after(hook_fargs6_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_MUNMAP) && route_client.munmap_6_6_after)
        route_client.munmap_6_6_after(args, route_client.context);
}

static void broker_mprotect_5_10_before(hook_fargs5_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_MPROTECT) && route_client.mprotect_5_10_before)
        route_client.mprotect_5_10_before(args, route_client.context);
}

static void broker_mprotect_5_10_after(hook_fargs5_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_MPROTECT) && route_client.mprotect_5_10_after)
        route_client.mprotect_5_10_after(args, route_client.context);
}

static void broker_mprotect_6_6_before(hook_fargs7_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_MPROTECT) && route_client.mprotect_6_6_before)
        route_client.mprotect_6_6_before(args, route_client.context);
}

static void broker_mprotect_6_6_after(hook_fargs7_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_MPROTECT) && route_client.mprotect_6_6_after)
        route_client.mprotect_6_6_after(args, route_client.context);
}

static void broker_copy_process_before(hook_fargs8_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_COPY_PROCESS) && route_client.copy_process_before)
        route_client.copy_process_before(args, route_client.context);
}

static void broker_copy_process_after(hook_fargs8_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_COPY_PROCESS) && route_client.copy_process_after)
        route_client.copy_process_after(args, route_client.context);
}

static void broker_begin_exec_before(hook_fargs1_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_BEGIN_EXEC) && route_client.begin_exec_before)
        route_client.begin_exec_before(args, route_client.context);
}

static void broker_begin_exec_after(hook_fargs1_t *args, void *unused)
{
    (void)unused;
    if (route_enabled(KP_KSH_ROUTE_BEGIN_EXEC) && route_client.begin_exec_after)
        route_client.begin_exec_after(args, route_client.context);
}

int kp_ksh_route_broker_init(void)
{
    void *mem_abort = (void *)kallsyms_lookup_name("do_mem_abort");
    void *exit_mmap = (void *)kallsyms_lookup_name("exit_mmap");
    void *copy_process = (void *)kallsyms_lookup_name("copy_process");
    void *begin_exec = (void *)kallsyms_lookup_name("begin_new_exec");
    void *munmap;
    void *mprotect;
    hook_err_t rc;

    if (route_installed_mask != 0u)
        return route_installed_mask == KP_KSH_ROUTE_ALL ? 0 : -EBUSY;
    munmap = (void *)kallsyms_lookup_name(
        kver == KP_KSH_KVER_ANDROID12_5_10_236 ? "do_munmap" : "do_vmi_munmap");
    mprotect = (void *)kallsyms_lookup_name("mprotect_fixup");
    if (!mem_abort || !exit_mmap || !munmap || !mprotect || !copy_process || !begin_exec)
        return -ENOSYS;
    rc = hook_wrap3(mem_abort, broker_mem_abort_before, 0, 0);
    if (rc != HOOK_NO_ERR) return -EINVAL;
    route_installed_mask |= KP_KSH_ROUTE_MEM_ABORT;
    rc = hook_wrap1(exit_mmap, broker_exit_mmap_before, broker_exit_mmap_after, 0);
    if (rc != HOOK_NO_ERR) return -EINVAL;
    route_installed_mask |= KP_KSH_ROUTE_EXIT_MMAP;
    if (kver == KP_KSH_KVER_ANDROID12_5_10_236) {
        rc = hook_wrap4(munmap, broker_munmap_5_10_before, broker_munmap_5_10_after, 0);
        if (rc == HOOK_NO_ERR)
            rc = hook_wrap5(mprotect, broker_mprotect_5_10_before, broker_mprotect_5_10_after, 0);
    } else if (kver == KP_KSH_KVER_ANDROID15_6_6_30) {
        rc = hook_wrap6(munmap, broker_munmap_6_6_before, broker_munmap_6_6_after, 0);
        if (rc == HOOK_NO_ERR)
            rc = hook_wrap7(mprotect, broker_mprotect_6_6_before, broker_mprotect_6_6_after, 0);
    } else {
        return -ENOSYS;
    }
    if (rc != HOOK_NO_ERR) return -EINVAL;
    route_installed_mask |= KP_KSH_ROUTE_MUNMAP | KP_KSH_ROUTE_MPROTECT;
    rc = hook_wrap8(copy_process, broker_copy_process_before, broker_copy_process_after, 0);
    if (rc != HOOK_NO_ERR) return -EINVAL;
    route_installed_mask |= KP_KSH_ROUTE_COPY_PROCESS;
    rc = hook_wrap1(begin_exec, broker_begin_exec_before, broker_begin_exec_after, 0);
    if (rc != HOOK_NO_ERR) return -EINVAL;
    route_installed_mask |= KP_KSH_ROUTE_BEGIN_EXEC;
    return 0;
}
KP_EXPORT_SYMBOL(kp_ksh_route_broker_init);

int kp_ksh_route_broker_register(const struct kp_ksh_route_client *client)
{
    if (!client || client->struct_size != sizeof(*client) ||
        client->abi_version != KP_KSH_ROUTE_BROKER_ABI_VERSION ||
        client->route_mask != KP_KSH_ROUTE_ALL || client->reserved != 0u ||
        client->reserved2[0] != 0u || client->reserved2[1] != 0u ||
        route_installed_mask != KP_KSH_ROUTE_ALL)
        return -EINVAL;
    if (__atomic_load_n(&route_registered, __ATOMIC_ACQUIRE) != 0u)
        return -EBUSY;
    memcpy(&route_client, client, sizeof(route_client));
    __atomic_store_n(&route_active_mask, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&route_registered, 1u, __ATOMIC_RELEASE);
    return 0;
}
KP_EXPORT_SYMBOL(kp_ksh_route_broker_register);

int kp_ksh_route_broker_set_mask(uint32_t mask)
{
    uint32_t current;

    if ((mask & ~KP_KSH_ROUTE_ALL) != 0u ||
        __atomic_load_n(&route_registered, __ATOMIC_ACQUIRE) == 0u)
        return -EINVAL;
    current = __atomic_load_n(&route_active_mask, __ATOMIC_ACQUIRE);
    if ((mask & current) != current)
        return -EPERM;
    __atomic_store_n(&route_active_mask, mask, __ATOMIC_RELEASE);
    return 0;
}
KP_EXPORT_SYMBOL(kp_ksh_route_broker_set_mask);

uint32_t kp_ksh_route_installed(void)
{
    return __atomic_load_n(&route_installed_mask, __ATOMIC_ACQUIRE);
}
KP_EXPORT_SYMBOL(kp_ksh_route_installed);

uint32_t kp_ksh_route_active(void)
{
    return __atomic_load_n(&route_active_mask, __ATOMIC_ACQUIRE);
}
KP_EXPORT_SYMBOL(kp_ksh_route_active);
