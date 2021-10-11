#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>


void bmLog(const char* func, const char* msg, ...) {
	va_list args;
	char* format;
	int formatLength;

	formatLength = 2 + 32 + strlen(func) + 3 + strlen(msg);
	format = (char*)malloc(formatLength);
	sprintf(format, "[%lu][%s]:%s\n", time(NULL), func, msg);
	va_start(args, msg);
	vfprintf(stderr, format, args);
	va_end(args);
	free(format);
}
