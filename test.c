
typedef struct wots_pkgen_args
{
    const xmss_params *params;
    unsigned char *pk;
    const unsigned char *pub_seed;
    uint32_t *addr;
    int start; 
    int end;
    int num;
} wots_pkgen_args_t;


void *wots_pkgen_sub(void *arg)
{

    wots_pkgen_args_t *args = arg;
    
    printf("%d, Thread number %ld\n", args->num, pthread_self());

    for (int i = args->start; i < args->end; i++)
    {
        set_chain_addr(args->addr, i);
        gen_chain(args->params, args->pk + i*(args->params->n), args->pk + i*(args->params->n),
                0, args->params->wots_w - 1, args->pub_seed, args->addr);
        
        // printf("%d: ", args->num);
        // for (int j = 0; j < 8; j++)
        // {
        //     printf("%04x", args->addr[j]);
        // }
        // printf("\n");
        // fflush(stdout);
    }
    return NULL;
}

void wots_pkgen(const xmss_params *params,
                unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    const uint32_t length = params->wots_len/NUM_CORES;
    const uint32_t leftover = params->wots_len % NUM_CORES; 

    uint32_t thread_addr[NUM_CORES + 1][8];

    // for (int j = 0; j < NUM_CORES + 1; j++) {
    //     memcpy(thread_addr[j], addr, sizeof(uint32_t) * 8);
    //     // for (int k = 0; k < 8; k++)
    //     // {
    //     //     thread_addr[j][k] = addr[k];
    //     // }
    // }

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, pk, seed);
    
    threadpool_t *pool = threadpool_create(NUM_CORES, NUM_CORES + 1, 0);

    wots_pkgen_args_t args[NUM_CORES + 1]; 
    
    pthread_t thread[NUM_CORES + 1]; 

    
    for (int j = 0; j < NUM_CORES + 1; j++)
    {
        // Parallel this loop
        // for (i = j*length; i < length*(j + 1); i++) 
        // {
        //     set_chain_addr(thread_addr[j], i);
        //     gen_chain(params, pk + i*params->n, pk + i*params->n,
        //             0, params->wots_w - 1, pub_seed, thread_addr[j]);
            
        //     printf("0: ");
        //     for (int k = 0; k < 8; k++)
        //     {
        //         printf("%04x", addr[k]);
        //     }
        //     printf("\n");
        // }
        // wots_pkgen_sub(params, pk, pub_seed, thread_addr[j], 
        //                 j*length, (j+1)*length);
        
        memcpy(thread_addr[j], addr, sizeof(uint32_t) * 8);
        args[j].addr = thread_addr[j]; 
        args[j].params = params; 
        args[j].pk = pk;
        args[j].pub_seed = pub_seed; 
        if (j == NUM_CORES)
        {
            args[j].start = params->wots_len - leftover; 
            args[j].end = params->wots_len;    
        }
        else
        {
            args[j].start = j*length; 
            args[j].end = (j+1)*length;
        }
        args[j].num = j;
        // printf("=====%d\n", j);
        
        // int status = pthread_create(&thread[j], NULL, wots_pkgen_sub, (void *) &args[j]);
        // if (status != 0) printf("status = %d\n", status);
        
        threadpool_add(pool, wots_pkgen_sub, &args[j], 0);
        
        // wots_pkgen_sub(&args[j]);
    }
    
    // Join threads, we don't care about return value
    // for (int j = 0; j < NUM_CORES + 1; j++) pthread_join(thread[j], NULL);
    
    threadpool_destroy(pool, 0);
}
