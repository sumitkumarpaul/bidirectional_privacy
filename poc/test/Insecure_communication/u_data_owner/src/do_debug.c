#include "do_debug.h"

int print_log(int debug_level, const char* format, ...)
{
    int ret;
    va_list args;
    struct timespec timestamp;
    struct timeval tv;
    struct timezone tz;
    struct tm *now;
    int zone;

    if (LOG_LEVEL >= debug_level)
    {
        gettimeofday(&tv,&tz);

        now = localtime(&tv.tv_sec);

        fprintf(PRINT_FILE, "[%02d-%02d-%04d %02d:%02d:%02d.%06ld] ", now->tm_mday, (now->tm_mon + 1), (now->tm_year + 1900), now->tm_hour, now->tm_min, now->tm_sec, tv.tv_usec);
        
        if (debug_level == DEBUG_LEVEL_INFO)
        {
            fprintf(PRINT_FILE, "Info:  ");
        }
        else if (debug_level == DEBUG_LEVEL_DUMP)
        {
            fprintf(PRINT_FILE, "Dump: ");
        }
        else if (debug_level == DEBUG_LEVEL_ERROR)
        {
            fprintf(PRINT_FILE, "Error: ");
        }
        
        va_start(args, format);
    
        ret = vfprintf(PRINT_FILE, format, args);
    
        va_end(args);
    }

    return ret;
}
