#ifndef DO_DEBUG_H
#define DO_DEBUG_H



#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#define DEBUG_LEVEL_NONE        (0)
#define DEBUG_LEVEL_SPECIAL     (1)
#define DEBUG_LEVEL_ERROR       (2)
#define DEBUG_LEVEL_INFO        (3)
#define DEBUG_LEVEL_DUMP        (4)

#define PRINT_FILE              stderr

int print_log(int debug_level, const char* format, ...);

#endif
