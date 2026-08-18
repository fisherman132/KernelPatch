/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "key_input.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

void key_input_secure_clear(void *buffer, size_t size)
{
    volatile unsigned char *cursor = (volatile unsigned char *)buffer;

    while (size-- > 0) {
        *cursor++ = 0;
    }
}

static int read_byte(int fd, unsigned char *byte)
{
    ssize_t count;

    do {
        count = read(fd, byte, 1);
    } while (count < 0 && errno == EINTR);

    if (count < 0) return -1;
    return count == 0 ? 0 : 1;
}

static key_input_status_t reject_input(char *buffer, size_t buffer_size,
                                       unsigned char *byte, key_input_status_t status)
{
    key_input_secure_clear(buffer, buffer_size);
    key_input_secure_clear(byte, sizeof(*byte));
    return status;
}

key_input_status_t key_input_resolve(const char *argument, int input_fd, char *buffer,
                                     size_t buffer_size, const char **resolved)
{
    size_t length = 0;
    int read_status;
    unsigned char byte = 0;
    bool terminated = false;

    if (!resolved) return KEY_INPUT_INVALID_ARGUMENT;
    *resolved = NULL;

    if (!argument) return KEY_INPUT_INVALID_ARGUMENT;
    if (strcmp(argument, "-") != 0) {
        *resolved = argument;
        return KEY_INPUT_OK;
    }
    if (!buffer || buffer_size < 2) return KEY_INPUT_INVALID_ARGUMENT;

    key_input_secure_clear(buffer, buffer_size);
    for (;;) {
        read_status = read_byte(input_fd, &byte);
        if (read_status < 0) {
            return reject_input(buffer, buffer_size, &byte, KEY_INPUT_READ_ERROR);
        }
        if (read_status == 0) break;
        if (byte == '\0') {
            return reject_input(buffer, buffer_size, &byte, KEY_INPUT_NUL_BYTE);
        }
        if (byte == '\n') {
            terminated = true;
            break;
        }
        if (byte == '\r') {
            read_status = read_byte(input_fd, &byte);
            if (read_status < 0) {
                return reject_input(buffer, buffer_size, &byte, KEY_INPUT_READ_ERROR);
            }
            if (read_status == 0 || byte != '\n') {
                return reject_input(buffer, buffer_size, &byte,
                                    KEY_INPUT_INVALID_LINE_ENDING);
            }
            terminated = true;
            break;
        }
        if (length >= buffer_size - 1) {
            return reject_input(buffer, buffer_size, &byte, KEY_INPUT_TOO_LONG);
        }
        buffer[length++] = (char)byte;
    }

    if (length == 0) {
        return reject_input(buffer, buffer_size, &byte, KEY_INPUT_EMPTY);
    }

    if (terminated) {
        read_status = read_byte(input_fd, &byte);
        if (read_status < 0) {
            return reject_input(buffer, buffer_size, &byte, KEY_INPUT_READ_ERROR);
        }
        if (read_status != 0) {
            return reject_input(buffer, buffer_size, &byte, KEY_INPUT_TRAILING_DATA);
        }
    }

    buffer[length] = '\0';
    *resolved = buffer;
    key_input_secure_clear(&byte, sizeof(byte));
    return KEY_INPUT_OK;
}

const char *key_input_status_message(key_input_status_t status)
{
    switch (status) {
    case KEY_INPUT_OK:
        return "success";
    case KEY_INPUT_INVALID_ARGUMENT:
        return "invalid reader argument";
    case KEY_INPUT_EMPTY:
        return "empty input";
    case KEY_INPUT_TOO_LONG:
        return "input is too long";
    case KEY_INPUT_NUL_BYTE:
        return "input contains a NUL byte";
    case KEY_INPUT_INVALID_LINE_ENDING:
        return "invalid line ending";
    case KEY_INPUT_TRAILING_DATA:
        return "data follows the first line";
    case KEY_INPUT_READ_ERROR:
        return "stdin read failed";
    default:
        return "unknown input error";
    }
}
