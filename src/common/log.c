/*
 * log.c
 *
 *  Created on: Aug 24, 2018
 *      Author: anlang
 */

#include <stdio.h>
#include <stdarg.h>

#include "log.h"

enum log_level g_log_level = LOG_LEVEL_DEBUG;

void log_print(int fd, const char*fmt, ...) {
	va_list ap;
	va_start(ap, fmt);

	vdprintf(fd, fmt, ap);
	va_end(ap);
}
