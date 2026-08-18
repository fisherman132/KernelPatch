/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bootimg.h"
#include "common.h"
#include "kpm.h"
#include "patch.h"
#include "x86_64.h"

bool log_enable = false;

static int matches(const char *actual, const char *expected)
{
    return actual && strcmp(actual, expected) == 0;
}

int patch_update_img(const char *kimg_path, const char *kpimg_path, const char *out_path,
                     const char *superkey, bool root_skey, const char **additional,
                     extra_config_t *extra_configs, int extra_config_num)
{
    (void)kpimg_path;
    (void)out_path;
    (void)additional;
    if (matches(kimg_path, "extra-name")) {
        return extra_config_num == 1 && extra_configs && extra_configs[0].is_path &&
                       matches(extra_configs[0].path, "fixture-extra.kpm") &&
                       matches(extra_configs[0].set_name, "device-profile")
                   ? 0
                   : 99;
    }
    (void)extra_configs;
    (void)extra_config_num;

    if (matches(kimg_path, "root-lf"))
        return root_skey && matches(superkey, "stdin-root-lf") ? 0 : 90;
    if (matches(kimg_path, "root-crlf"))
        return root_skey && matches(superkey, "stdin-root-crlf") ? 0 : 91;
    if (matches(kimg_path, "plain-lf"))
        return !root_skey && matches(superkey, "stdin-plain-lf") ? 0 : 92;
    if (matches(kimg_path, "plain-crlf"))
        return !root_skey && matches(superkey, "stdin-plain-crlf") ? 0 : 93;
    if (matches(kimg_path, "max-lf")) {
        if (!root_skey || !superkey || strlen(superkey) != SUPER_KEY_LEN - 1) return 97;
        for (size_t i = 0; i < SUPER_KEY_LEN - 1; i++) {
            if (superkey[i] != 'x') return 98;
        }
        return 0;
    }
    if (matches(kimg_path, "literal-plain"))
        return !root_skey && matches(superkey, "literal-normal-key") ? 0 : 94;
    if (matches(kimg_path, "literal-root"))
        return root_skey && matches(superkey, "literal-root-key") ? 0 : 95;

    /* Rejected stdin must never reach the patch operation. */
    return 96;
}

uint32_t get_kpimg_version(const char *path)
{
    (void)path;
    return 0;
}

int extra_str_type(const char *extra_str)
{
    return matches(extra_str, "kpm") ? EXTRA_TYPE_KPM : EXTRA_TYPE_NONE;
}

int unpatch_img(const char *input, const char *output)
{
    (void)input;
    (void)output;
    return 0;
}

int reset_key(const char *input, const char *output, const char *key)
{
    (void)output;
    if (matches(input, "reset-stdin")) return matches(key, "stdin-reset-lf") ? 0 : 88;
    return key ? 0 : 89;
}

int dump_kallsym(const char *path)
{
    (void)path;
    return 0;
}

int dump_ikconfig(const char *path)
{
    (void)path;
    return 0;
}

int print_image_patch_info_path(const char *path)
{
    (void)path;
    return 0;
}

int print_kp_image_info_path(const char *path)
{
    (void)path;
    return 0;
}

int print_kpm_info_path(const char *path)
{
    (void)path;
    return 0;
}

int extract_kernel(const char *path)
{
    (void)path;
    return 0;
}

int repack_bootimg(const char *input, const char *kernel, const char *output)
{
    (void)input;
    (void)kernel;
    (void)output;
    return 0;
}

int cacluate_sha1(const char *path)
{
    (void)path;
    return 0;
}

int load_x86_bzimage(const char *path, x86_bzimage_t *image)
{
    (void)path;
    (void)image;
    return -1;
}

int write_x86_bzimage(x86_bzimage_t *image, const char *path)
{
    (void)image;
    (void)path;
    return -1;
}

void free_x86_bzimage(x86_bzimage_t *image)
{
    (void)image;
}

void write_file(const char *path, const char *contents, int length, bool append)
{
    (void)path;
    (void)contents;
    (void)length;
    (void)append;
}
