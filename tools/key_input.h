/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_TOOL_KEY_INPUT_H_
#define _KP_TOOL_KEY_INPUT_H_

#include <stddef.h>

typedef enum
{
    KEY_INPUT_OK = 0,
    KEY_INPUT_INVALID_ARGUMENT,
    KEY_INPUT_EMPTY,
    KEY_INPUT_TOO_LONG,
    KEY_INPUT_NUL_BYTE,
    KEY_INPUT_INVALID_LINE_ENDING,
    KEY_INPUT_TRAILING_DATA,
    KEY_INPUT_READ_ERROR,
} key_input_status_t;

/*
 * Resolve a key option. Literal values are returned unchanged. A value exactly
 * equal to "-" is read from input_fd into buffer as one bounded line.
 */
key_input_status_t key_input_resolve(const char *argument, int input_fd, char *buffer,
                                     size_t buffer_size, const char **resolved);

const char *key_input_status_message(key_input_status_t status);

/* Wipe key material with volatile stores so the compiler cannot elide it. */
void key_input_secure_clear(void *buffer, size_t size);

#endif
