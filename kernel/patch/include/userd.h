/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_USERD_H_
#define _KP_USERD_H_

#include <ktypes.h>

int load_ap_package_config(void);

#ifdef ANDROID
int refresh_trusted_manager_uid(void);
int refresh_trusted_manager_state(void);
int resolve_trusted_manager_apd_path(uid_t caller_uid, char *path, size_t path_len);
int trusted_manager_androidpatch_action(uid_t caller_uid, int action);
int trusted_manager_androidpatch_exec(char **__user u_filename_p,
                                      char **__user uargv);

uid_t get_trusted_manager_uid(void);
int is_trusted_manager_uid_android(uid_t uid);
#endif

int is_trusted_manager_uid(uid_t uid);

#endif
