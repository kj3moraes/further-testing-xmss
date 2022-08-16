#include "thread_wrapper.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* 
 * By default, assume CPU has 2 core, 4 maximum threads, 
 * but we only use XMSS_num_cores parameter, so 1 threads in use
 */
unsigned int XMSS_num_cores = 4, 
             XMSS_num_cores_max = 8;


/* 
 * Find number of CPUs in run time
 */
static
int XMSS_find_number_of_cpus(void)
{
#ifdef _WIN32
    #ifndef _SC_NPROCESSORS_ONLN
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        #define sysconf(a) info.dwNumberOfProcessors
        #define _SC_NPROCESSORS_ONLN
    #endif
#endif


/*
 * For Linux
 */
#ifdef _SC_NPROCESSORS_ONLN

    XMSS_num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (XMSS_num_cores < 1)
    {
        XMSS_num_cores = 2;
    }
    if (XMSS_num_cores > 4)
    {
        XMSS_num_cores = 4;
    }

    XMSS_num_cores_max = sysconf(_SC_NPROCESSORS_CONF);
    if (XMSS_num_cores_max < 1)
    {
        XMSS_num_cores_max = XMSS_num_cores * 2;
    }

    return 0;
#else
    /* 
     * By default set to the smallest number of cores
     */
    XMSS_num_cores = 1;
    XMSS_num_cores_max = 2;
    return 1;
#endif
}

/* 
 * Find CPU at runtime, this only run once
 * Return 0 success, 1 error
 */
int XMSS_search_cpu(void)
{
    static int found_cpu = 0;
    if (!found_cpu)
    {
        if (XMSS_find_number_of_cpus())
        {
            fprintf(stderr, "Could not determine number of CPUs");
            found_cpu = 1;
            return EBADR;
        }
#if DEBUG
        printf("[XMSS] - Use %d of %d processors online\n", XMSS_num_cores, XMSS_num_cores_max);
#endif
        found_cpu = 1;
    }
    return 0;
}
