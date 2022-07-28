#ifndef THREAD_WRAPPER_H
#define THREAD_WRAPPER_H

#include "nist_params.h"

extern unsigned int XMSS_num_cores;
extern unsigned int XMSS_num_cores_max;

int XMSS_search_cpu(void);

/*
 * Because the last iteration of WOTS chain only run with small iterations, 
 * so we can spend extra thread to handle small iterations,
 * let the main thread to be free to wait for child threads
 */
#define NUM_CORES XMSS_num_cores
#define THREAD_NUMBERS (NUM_CORES + 1)

#if POSIX_THREAD == 1
    #include <pthread.h>

#else

    /*
    * Simple thread wrapper for Window API
    */
    #include <windows.h>

    typedef HANDLE pthread_t;

    int pthread_create(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
    {
        void(attr);

        if (thread == NULL || start_routine == NULL)
            return 1;

        *thread = CreateThread(NULL,       // Thread attributes
                            0,             // Stack size (0 = use default)
                            start_routine, // Thread start address
                            arg,           // Parameter to pass to the thread
                            0,             // Creation flags
                            NULL);         // Thread id

        if (*thread == NULL)
        {
            // Thread creation failed
            return 1;
        }
        return 0;
    }

    int pthread_join(pthread_t thread, void **value_ptr)
    {
        (void)value_ptr;
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        return 0;
    }

#endif

#endif /* THREAD_WRAPPER_H */
