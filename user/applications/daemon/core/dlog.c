#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include "dlog.h"

static pthread_mutex_t dlog_mutex = PTHREAD_MUTEX_INITIALIZER;

void ddebug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    pthread_mutex_lock(&dlog_mutex);
    vprintf(fmt, args);
    pthread_mutex_unlock(&dlog_mutex);
    va_end(args);
}

void dprint(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    pthread_mutex_lock(&dlog_mutex);
    vprintf(fmt, args);
    pthread_mutex_unlock(&dlog_mutex);
    va_end(args);
}

void derror(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    pthread_mutex_lock(&dlog_mutex);
    vprintf(fmt, args);
    pthread_mutex_unlock(&dlog_mutex);
    va_end(args);
}

void demerg(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    pthread_mutex_lock(&dlog_mutex);
    vprintf(fmt, args);
    pthread_mutex_unlock(&dlog_mutex);
    va_end(args);
}
