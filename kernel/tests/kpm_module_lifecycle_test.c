/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODEL_MAX_MODULES 16U
#define MODEL_NAME_LEN 32U
#define MODEL_ARG_LEN 64U

enum module_state {
    MODULE_LOADING = 0,
    MODULE_LIVE,
    MODULE_EXITING,
    MODULE_INIT_FAILED,
};

struct model_registry;
struct model_module;

typedef long (*model_init_fn)(struct model_module *module, void *opaque);
typedef long (*model_control_fn)(struct model_module *module, char *args, void *opaque);
typedef long (*model_event_fn)(struct model_module *module, const char *event, void *opaque);
typedef long (*model_exit_fn)(struct model_module *module, void *opaque);

struct model_callbacks {
    model_init_fn init;
    model_control_fn control;
    model_event_fn event;
    model_exit_fn exit;
};

struct model_module {
    struct model_registry *registry;
    char name[MODEL_NAME_LEN];
    enum module_state state;
    unsigned int active_calls;
    long init_rc;
    long exit_rc;
    struct model_callbacks callbacks;
    void *opaque;
    char *ctl_args;
    bool ctl_active;
};

struct model_registry {
    struct model_module *modules[MODEL_MAX_MODULES];
    size_t count;
    unsigned int allocations;
    unsigned int frees;
    unsigned int grace_periods;
};

struct callback_fixture {
    struct model_registry *registry;
    const char *nested_name;
    const char *event_unload_name;
    long init_result;
    long control_result;
    long event_result;
    long exit_result;
    long nested_load_rc;
    long nested_unload_rc;
    unsigned int init_calls;
    unsigned int control_calls;
    unsigned int event_calls;
    unsigned int exit_calls;
    bool nested_load_on_init;
    bool nested_unload_on_control;
    bool nested_unload_on_event;
    bool nested_unload_on_exit;
    bool probe_callbacks_on_exit;
    bool mutate_control_args;
    enum module_state exit_observed_state;
    long exit_control_rc;
    long exit_event_rc;
    char last_control_args[MODEL_ARG_LEN];
};

static long model_load(struct model_registry *registry, const char *name,
                       const struct model_callbacks *callbacks, void *opaque,
                       struct model_module **retained);
static long model_unload(struct model_registry *registry, const char *name);

static long fixture_init(struct model_module *module, void *opaque);
static long fixture_control(struct model_module *module, char *args, void *opaque);
static long fixture_event(struct model_module *module, const char *event, void *opaque);
static long fixture_exit(struct model_module *module, void *opaque);

static const struct model_callbacks fixture_callbacks = {
    .init = fixture_init,
    .control = fixture_control,
    .event = fixture_event,
    .exit = fixture_exit,
};

static void fail_check(const char *test, const char *expression, const char *file, int line)
{
    fprintf(stderr, "[FAIL] %s: %s (%s:%d)\n", test, expression, file, line);
    exit(EXIT_FAILURE);
}

#define CHECK(test, expression)                                                                         \
    do {                                                                                                \
        if (!(expression)) fail_check((test), #expression, __FILE__, __LINE__);                         \
    } while (0)

#define CHECK_LONG(test, expected, actual)                                                              \
    do {                                                                                                \
        long check_expected = (long)(expected);                                                         \
        long check_actual = (long)(actual);                                                             \
        if (check_expected != check_actual) {                                                           \
            char check_expression[160];                                                                \
            (void)snprintf(check_expression, sizeof(check_expression), "expected %ld, got %ld",       \
                           check_expected, check_actual);                                               \
            fail_check((test), check_expression, __FILE__, __LINE__);                                  \
        }                                                                                               \
    } while (0)

static void registry_init(struct model_registry *registry)
{
    memset(registry, 0, sizeof(*registry));
}

static struct callback_fixture fixture_make(struct model_registry *registry)
{
    struct callback_fixture fixture;

    memset(&fixture, 0, sizeof(fixture));
    fixture.registry = registry;
    fixture.nested_load_rc = -9999;
    fixture.nested_unload_rc = -9999;
    fixture.exit_control_rc = -9999;
    fixture.exit_event_rc = -9999;
    fixture.exit_observed_state = MODULE_EXITING;
    return fixture;
}

static struct model_module *registry_find(const struct model_registry *registry, const char *name)
{
    size_t i;

    for (i = 0; i < registry->count; ++i) {
        if (strcmp(registry->modules[i]->name, name) == 0) return registry->modules[i];
    }
    return NULL;
}

static int registry_append(struct model_registry *registry, struct model_module *module)
{
    if (registry->count == MODEL_MAX_MODULES) return -ENOSPC;
    registry->modules[registry->count++] = module;
    return 0;
}

static void registry_remove(struct model_registry *registry, struct model_module *module)
{
    size_t i;

    for (i = 0; i < registry->count; ++i) {
        if (registry->modules[i] == module) {
            size_t remaining = registry->count - i - 1U;

            if (remaining != 0U) {
                memmove(&registry->modules[i], &registry->modules[i + 1U],
                        remaining * sizeof(registry->modules[0]));
            }
            registry->count--;
            registry->modules[registry->count] = NULL;
            return;
        }
    }
    abort();
}

static void model_synchronize_rcu(struct model_registry *registry)
{
    registry->grace_periods++;
}

static void model_free_module(struct model_registry *registry, struct model_module *module)
{
    if (module->active_calls != 0U) abort();
    free(module->ctl_args);
    registry->frees++;
    free(module);
}

static int model_begin_call(struct model_module *module)
{
    if (module->state != MODULE_LIVE) return -EBUSY;
    module->active_calls++;
    return 0;
}

static void model_end_call(struct model_module *module)
{
    if (module->active_calls == 0U) abort();
    module->active_calls--;
}

static int model_try_get_live_after_initial_check(struct model_module *module,
                                                  void (*interleave)(struct model_module *))
{
    if (module->state != MODULE_LIVE) return -EBUSY;
    if (interleave) interleave(module);
    module->active_calls++;
    if (module->state != MODULE_LIVE) {
        module->active_calls--;
        return -EBUSY;
    }
    return 0;
}

static long model_load(struct model_registry *registry, const char *name,
                       const struct model_callbacks *callbacks, void *opaque,
                       struct model_module **retained)
{
    struct model_module *module;
    size_t name_len;
    long init_rc;
    int append_rc;

    if (retained) *retained = NULL;
    if (!registry || !name || !callbacks || !callbacks->init || !callbacks->exit) return -EINVAL;

    name_len = strlen(name);
    if (name_len == 0U || name_len >= MODEL_NAME_LEN) return -EINVAL;

    /* LOADING and INIT_FAILED entries reserve the name just like LIVE entries. */
    if (registry_find(registry, name)) return -EEXIST;

    module = calloc(1U, sizeof(*module));
    if (!module) return -ENOMEM;
    registry->allocations++;

    module->registry = registry;
    memcpy(module->name, name, name_len + 1U);
    module->state = MODULE_LOADING;
    module->callbacks = *callbacks;
    module->opaque = opaque;

    append_rc = registry_append(registry, module);
    if (append_rc != 0) {
        model_free_module(registry, module);
        return append_rc;
    }

    init_rc = module->callbacks.init(module, module->opaque);
    module->init_rc = init_rc;
    if (init_rc == 0) {
        module->state = MODULE_LIVE;
        if (retained) *retained = module;
        return 0;
    }

    module->exit_rc = module->callbacks.exit(module, module->opaque);
    if (module->exit_rc != 0) {
        module->state = MODULE_INIT_FAILED;
        if (retained) *retained = module;
        return init_rc;
    }

    module->state = MODULE_EXITING;
    registry_remove(registry, module);
    model_synchronize_rcu(registry);
    model_free_module(registry, module);
    return init_rc;
}

static long model_control(struct model_registry *registry, const char *name, const char *args)
{
    struct model_module *module;
    char *new_args;
    char *old_args;
    size_t args_len;
    long rc;

    if (!registry || !name || !args) return -EINVAL;
    module = registry_find(registry, name);
    if (!module) return -ENOENT;
    if (!module->callbacks.control) return -ENOSYS;

    rc = model_begin_call(module);
    if (rc != 0) return rc;
    if (module->ctl_active) {
        model_end_call(module);
        return -EBUSY;
    }
    module->ctl_active = true;

    args_len = strlen(args);
    new_args = malloc(args_len + 1U);
    if (!new_args) {
        module->ctl_active = false;
        model_end_call(module);
        return -ENOMEM;
    }
    memcpy(new_args, args, args_len + 1U);

    old_args = module->ctl_args;
    module->ctl_args = new_args;
    free(old_args);
    rc = module->callbacks.control(module, module->ctl_args, module->opaque);
    module->ctl_active = false;
    model_end_call(module);
    return rc;
}

static long model_notify_event(struct model_registry *registry, const char *event)
{
    struct model_module *cursor = NULL;
    long first_error = 0;
    long calls = 0;

    if (!registry || !event) return -EINVAL;

    for (;;) {
        struct model_module *selected = NULL;
        size_t start = 0U;
        size_t i;
        long rc;

        if (cursor) {
            for (i = 0U; i < registry->count; ++i) {
                if (registry->modules[i] == cursor) {
                    start = i + 1U;
                    break;
                }
            }
            if (i == registry->count) abort();
        }

        for (i = start; i < registry->count; ++i) {
            struct model_module *candidate = registry->modules[i];

            if (!candidate->callbacks.event || model_begin_call(candidate) != 0) continue;
            selected = candidate;
            break;
        }

        if (cursor) model_end_call(cursor);
        cursor = selected;
        if (!cursor) break;

        rc = cursor->callbacks.event(cursor, event, cursor->opaque);
        if (rc < 0 && first_error == 0) first_error = rc;
        calls++;
    }

    return first_error != 0 ? first_error : calls;
}

static long model_unload(struct model_registry *registry, const char *name)
{
    struct model_module *module;
    enum module_state restore_state;
    long rc;

    if (!registry || !name) return -EINVAL;
    module = registry_find(registry, name);
    if (!module) return -ENOENT;
    if (module->state != MODULE_LIVE && module->state != MODULE_INIT_FAILED) return -EBUSY;

    restore_state = module->state;
    module->state = MODULE_EXITING;
    if (module->active_calls != 0U) {
        module->state = restore_state;
        return -EBUSY;
    }
    rc = module->callbacks.exit(module, module->opaque);
    module->exit_rc = rc;
    if (rc != 0) {
        /* Exit vetoes must not change membership or list position. */
        module->state = restore_state;
        return rc;
    }

    registry_remove(registry, module);
    model_synchronize_rcu(registry);
    model_free_module(registry, module);
    return 0;
}

static long fixture_init(struct model_module *module, void *opaque)
{
    struct callback_fixture *fixture = opaque;

    fixture->init_calls++;
    if (fixture->nested_load_on_init) {
        const char *name = fixture->nested_name ? fixture->nested_name : module->name;

        fixture->nested_load_rc =
            model_load(fixture->registry, name, &fixture_callbacks, fixture, NULL);
    }
    return fixture->init_result;
}

static long fixture_control(struct model_module *module, char *args, void *opaque)
{
    struct callback_fixture *fixture = opaque;

    fixture->control_calls++;
    (void)snprintf(fixture->last_control_args, sizeof(fixture->last_control_args), "%s", args);
    if (fixture->mutate_control_args && args[0] != '\0') args[0] = 'X';
    if (fixture->nested_unload_on_control) {
        fixture->nested_unload_rc = model_unload(fixture->registry, module->name);
    }
    return fixture->control_result;
}

static long fixture_event(struct model_module *module, const char *event, void *opaque)
{
    struct callback_fixture *fixture = opaque;

    (void)event;
    fixture->event_calls++;
    if (fixture->nested_unload_on_event) {
        const char *name = fixture->event_unload_name ? fixture->event_unload_name : module->name;

        fixture->nested_unload_rc = model_unload(fixture->registry, name);
    }
    return fixture->event_result;
}

static long fixture_exit(struct model_module *module, void *opaque)
{
    struct callback_fixture *fixture = opaque;

    fixture->exit_calls++;
    fixture->exit_observed_state = module->state;
    if (fixture->probe_callbacks_on_exit) {
        fixture->exit_control_rc = model_control(fixture->registry, module->name, "during-exit");
        fixture->exit_event_rc = model_notify_event(fixture->registry, "during-exit");
    }
    if (fixture->nested_unload_on_exit) {
        fixture->nested_unload_rc = model_unload(fixture->registry, module->name);
    }
    return fixture->exit_result;
}

static void check_order(const char *test, const struct model_registry *registry,
                        const char *const *names, size_t count)
{
    size_t i;

    CHECK(test, registry->count == count);
    for (i = 0; i < count; ++i) CHECK(test, strcmp(registry->modules[i]->name, names[i]) == 0);
}

static void test_normal_lifecycle_and_reload(void)
{
    static const char test[] = "normal load/control/event/unload/reload";
    struct model_registry registry;
    struct callback_fixture fixture;
    struct callback_fixture reloaded;
    struct model_module *module = NULL;
    char caller_args[] = "ping";

    registry_init(&registry);
    fixture = fixture_make(&registry);
    fixture.control_result = 17;
    fixture.mutate_control_args = true;

    CHECK_LONG(test, 0, model_load(&registry, "normal", &fixture_callbacks, &fixture, &module));
    CHECK(test, module != NULL);
    CHECK(test, module->state == MODULE_LIVE);
    CHECK_LONG(test, 0, module->active_calls);
    CHECK_LONG(test, 1, fixture.init_calls);

    CHECK_LONG(test, 17, model_control(&registry, "normal", caller_args));
    CHECK(test, strcmp(caller_args, "ping") == 0);
    CHECK(test, strcmp(fixture.last_control_args, "ping") == 0);
    CHECK_LONG(test, 1, fixture.control_calls);
    CHECK_LONG(test, 0, module->active_calls);
    CHECK(test, strcmp(module->ctl_args, "Xing") == 0);

    CHECK_LONG(test, 1, model_notify_event(&registry, "ready"));
    CHECK_LONG(test, 1, fixture.event_calls);
    CHECK_LONG(test, 0, module->active_calls);

    CHECK_LONG(test, 0, model_unload(&registry, "normal"));
    CHECK_LONG(test, 0, registry.count);
    CHECK_LONG(test, 1, fixture.exit_calls);
    CHECK(test, fixture.exit_observed_state == MODULE_EXITING);
    CHECK_LONG(test, 1, registry.frees);
    CHECK_LONG(test, 1, registry.grace_periods);

    reloaded = fixture_make(&registry);
    CHECK_LONG(test, 0, model_load(&registry, "normal", &fixture_callbacks, &reloaded, NULL));
    CHECK_LONG(test, 0, model_unload(&registry, "normal"));
    CHECK_LONG(test, 2, registry.allocations);
    CHECK_LONG(test, 2, registry.frees);
}

static void test_exit_veto_preserves_order_and_recovers_control(void)
{
    static const char test[] = "exit veto preserves order and recovers control";
    static const char *const initial_order[] = { "first", "middle", "last" };
    static const char *const final_order[] = { "first", "last" };
    struct model_registry registry;
    struct callback_fixture first;
    struct callback_fixture middle;
    struct callback_fixture last;
    struct model_module *middle_module;

    registry_init(&registry);
    first = fixture_make(&registry);
    middle = fixture_make(&registry);
    last = fixture_make(&registry);
    middle.exit_result = -EPERM;
    middle.control_result = 23;
    middle.probe_callbacks_on_exit = true;

    CHECK_LONG(test, 0, model_load(&registry, "first", &fixture_callbacks, &first, NULL));
    CHECK_LONG(test, 0, model_load(&registry, "middle", &fixture_callbacks, &middle, NULL));
    CHECK_LONG(test, 0, model_load(&registry, "last", &fixture_callbacks, &last, NULL));
    check_order(test, &registry, initial_order, 3U);

    middle_module = registry_find(&registry, "middle");
    CHECK(test, middle_module != NULL);
    CHECK_LONG(test, -EPERM, model_unload(&registry, "middle"));
    CHECK(test, middle_module->state == MODULE_LIVE);
    CHECK_LONG(test, -EBUSY, middle.exit_control_rc);
    CHECK_LONG(test, 2, middle.exit_event_rc);
    CHECK_LONG(test, 0, middle.control_calls);
    CHECK_LONG(test, 0, middle.event_calls);
    CHECK_LONG(test, 0, registry.frees);
    CHECK_LONG(test, 0, registry.grace_periods);
    check_order(test, &registry, initial_order, 3U);
    CHECK_LONG(test, 23, model_control(&registry, "middle", "after-veto"));
    CHECK_LONG(test, 1, middle.control_calls);

    middle.exit_result = 0;
    CHECK_LONG(test, 0, model_unload(&registry, "middle"));
    check_order(test, &registry, final_order, 2U);
    CHECK_LONG(test, 0, model_unload(&registry, "first"));
    CHECK_LONG(test, 0, model_unload(&registry, "last"));
    CHECK_LONG(test, 3, registry.frees);
}

static void test_init_failure_cleanup_success_is_not_retained(void)
{
    static const char test[] = "init failure with successful cleanup is not retained";
    struct model_registry registry;
    struct callback_fixture fixture;
    struct model_module *retained = (struct model_module *)(void *)&registry;

    registry_init(&registry);
    fixture = fixture_make(&registry);
    fixture.init_result = -EINVAL;

    CHECK_LONG(test, -EINVAL,
               model_load(&registry, "init-fail-clean", &fixture_callbacks, &fixture, &retained));
    CHECK(test, retained == NULL);
    CHECK_LONG(test, 1, fixture.init_calls);
    CHECK_LONG(test, 1, fixture.exit_calls);
    CHECK(test, fixture.exit_observed_state == MODULE_LOADING);
    CHECK_LONG(test, 0, registry.count);
    CHECK_LONG(test, 1, registry.allocations);
    CHECK_LONG(test, 1, registry.frees);
}

static void test_init_failure_cleanup_veto_is_retryable(void)
{
    static const char test[] = "init failure with cleanup veto is retained and retryable";
    struct model_registry registry;
    struct callback_fixture fixture;
    struct callback_fixture duplicate;
    struct model_module *retained = NULL;

    registry_init(&registry);
    fixture = fixture_make(&registry);
    fixture.init_result = -EINVAL;
    fixture.exit_result = -EAGAIN;

    CHECK_LONG(test, -EINVAL,
               model_load(&registry, "init-fail-veto", &fixture_callbacks, &fixture, &retained));
    CHECK(test, retained != NULL);
    CHECK(test, retained->state == MODULE_INIT_FAILED);
    CHECK_LONG(test, -EINVAL, retained->init_rc);
    CHECK_LONG(test, -EAGAIN, retained->exit_rc);
    CHECK(test, fixture.exit_observed_state == MODULE_LOADING);
    CHECK_LONG(test, 1, registry.count);
    CHECK_LONG(test, 0, registry.frees);

    CHECK_LONG(test, -EBUSY, model_control(&registry, "init-fail-veto", "rejected"));
    CHECK_LONG(test, 0, model_notify_event(&registry, "rejected"));
    CHECK_LONG(test, 0, fixture.control_calls);
    CHECK_LONG(test, 0, fixture.event_calls);

    duplicate = fixture_make(&registry);
    CHECK_LONG(test, -EEXIST,
               model_load(&registry, "init-fail-veto", &fixture_callbacks, &duplicate, NULL));
    CHECK_LONG(test, 0, duplicate.init_calls);
    CHECK_LONG(test, 1, registry.allocations);

    CHECK_LONG(test, -EAGAIN, model_unload(&registry, "init-fail-veto"));
    CHECK(test, retained->state == MODULE_INIT_FAILED);
    CHECK_LONG(test, 1, registry.count);
    CHECK_LONG(test, 0, registry.frees);

    fixture.exit_result = 0;
    CHECK_LONG(test, 0, model_unload(&registry, "init-fail-veto"));
    CHECK_LONG(test, 0, registry.count);
    CHECK_LONG(test, 1, registry.frees);
    CHECK_LONG(test, 3, fixture.exit_calls);
}

static void test_active_callback_blocks_unload(void)
{
    static const char test[] = "active callback blocks exit and free";
    struct model_registry registry;
    struct callback_fixture fixture;
    struct model_module *module = NULL;

    registry_init(&registry);
    fixture = fixture_make(&registry);
    fixture.control_result = 29;
    fixture.nested_unload_on_control = true;

    CHECK_LONG(test, 0, model_load(&registry, "active", &fixture_callbacks, &fixture, &module));
    CHECK_LONG(test, 29, model_control(&registry, "active", "hold"));
    CHECK_LONG(test, -EBUSY, fixture.nested_unload_rc);
    CHECK_LONG(test, 0, fixture.exit_calls);
    CHECK_LONG(test, 0, registry.frees);
    CHECK_LONG(test, 0, registry.grace_periods);
    CHECK(test, module->state == MODULE_LIVE);
    CHECK_LONG(test, 0, module->active_calls);

    CHECK_LONG(test, 0, model_unload(&registry, "active"));
    CHECK_LONG(test, 1, fixture.exit_calls);
    CHECK_LONG(test, 1, registry.frees);

    fixture = fixture_make(&registry);
    fixture.nested_unload_on_event = true;
    CHECK_LONG(test, 0, model_load(&registry, "active-event", &fixture_callbacks, &fixture, NULL));
    CHECK_LONG(test, 1, model_notify_event(&registry, "hold"));
    CHECK_LONG(test, -EBUSY, fixture.nested_unload_rc);
    CHECK_LONG(test, 0, fixture.exit_calls);
    CHECK_LONG(test, 1, registry.frees);
    CHECK_LONG(test, 0, model_unload(&registry, "active-event"));
    CHECK_LONG(test, 1, fixture.exit_calls);
    CHECK_LONG(test, 2, registry.frees);
}

static void interleave_mark_exiting(struct model_module *module)
{
    module->state = MODULE_EXITING;
}

static void test_acquire_rechecks_state_after_increment(void)
{
    static const char test[] = "callback acquire rechecks state after increment";
    struct model_registry registry;
    struct callback_fixture fixture;
    struct model_module *module = NULL;

    registry_init(&registry);
    fixture = fixture_make(&registry);
    CHECK_LONG(test, 0, model_load(&registry, "acquire-race", &fixture_callbacks, &fixture, &module));
    CHECK_LONG(test, -EBUSY,
               model_try_get_live_after_initial_check(module, interleave_mark_exiting));
    CHECK(test, module->state == MODULE_EXITING);
    CHECK_LONG(test, 0, module->active_calls);
    CHECK_LONG(test, 0, fixture.control_calls);

    module->state = MODULE_LIVE;
    CHECK_LONG(test, 0, model_unload(&registry, "acquire-race"));
}

static void test_event_removal_of_successor_keeps_traversal_safe(void)
{
    static const char test[] = "event callback can retire its successor safely";
    struct model_registry registry;
    struct callback_fixture first;
    struct callback_fixture removed;
    struct callback_fixture last;

    registry_init(&registry);
    first = fixture_make(&registry);
    removed = fixture_make(&registry);
    last = fixture_make(&registry);
    first.nested_unload_on_event = true;
    first.event_unload_name = "event-removed";

    CHECK_LONG(test, 0, model_load(&registry, "event-first", &fixture_callbacks, &first, NULL));
    CHECK_LONG(test, 0, model_load(&registry, "event-removed", &fixture_callbacks, &removed, NULL));
    CHECK_LONG(test, 0, model_load(&registry, "event-last", &fixture_callbacks, &last, NULL));

    CHECK_LONG(test, 2, model_notify_event(&registry, "retire-next"));
    CHECK_LONG(test, 0, first.nested_unload_rc);
    CHECK_LONG(test, 1, first.event_calls);
    CHECK_LONG(test, 0, removed.event_calls);
    CHECK_LONG(test, 1, removed.exit_calls);
    CHECK_LONG(test, 1, last.event_calls);
    CHECK_LONG(test, 1, registry.frees);

    CHECK_LONG(test, 0, model_unload(&registry, "event-first"));
    CHECK_LONG(test, 0, model_unload(&registry, "event-last"));
    CHECK_LONG(test, 3, registry.frees);
}

static void test_exiting_and_double_unload_are_rejected(void)
{
    static const char test[] = "EXITING and double unload are rejected";
    struct model_registry registry;
    struct callback_fixture fixture;

    registry_init(&registry);
    fixture = fixture_make(&registry);
    fixture.nested_unload_on_exit = true;

    CHECK_LONG(test, 0, model_load(&registry, "double", &fixture_callbacks, &fixture, NULL));
    CHECK_LONG(test, 0, model_unload(&registry, "double"));
    CHECK_LONG(test, -EBUSY, fixture.nested_unload_rc);
    CHECK_LONG(test, 1, fixture.exit_calls);
    CHECK_LONG(test, 1, registry.frees);
    CHECK_LONG(test, -ENOENT, model_unload(&registry, "double"));
    CHECK_LONG(test, 1, fixture.exit_calls);
}

static void test_loading_name_is_unique(void)
{
    static const char test[] = "same-name loading reservation is unique";
    struct model_registry registry;
    struct callback_fixture fixture;
    struct callback_fixture reloaded;

    registry_init(&registry);
    fixture = fixture_make(&registry);
    fixture.nested_load_on_init = true;

    CHECK_LONG(test, 0, model_load(&registry, "unique", &fixture_callbacks, &fixture, NULL));
    CHECK_LONG(test, -EEXIST, fixture.nested_load_rc);
    CHECK_LONG(test, 1, fixture.init_calls);
    CHECK_LONG(test, 1, registry.allocations);
    CHECK_LONG(test, -EEXIST,
               model_load(&registry, "unique", &fixture_callbacks, &fixture, NULL));
    CHECK_LONG(test, 1, registry.allocations);

    CHECK_LONG(test, 0, model_unload(&registry, "unique"));
    reloaded = fixture_make(&registry);
    CHECK_LONG(test, 0, model_load(&registry, "unique", &fixture_callbacks, &reloaded, NULL));
    CHECK_LONG(test, 0, model_unload(&registry, "unique"));
    CHECK_LONG(test, 2, registry.allocations);
    CHECK_LONG(test, 2, registry.frees);
}

int main(void)
{
    test_normal_lifecycle_and_reload();
    test_exit_veto_preserves_order_and_recovers_control();
    test_init_failure_cleanup_success_is_not_retained();
    test_init_failure_cleanup_veto_is_retryable();
    test_active_callback_blocks_unload();
    test_acquire_rechecks_state_after_increment();
    test_event_removal_of_successor_keeps_traversal_safe();
    test_exiting_and_double_unload_are_rejected();
    test_loading_name_is_unique();

    puts("[PASS] KPM module lifecycle host model");
    return EXIT_SUCCESS;
}
