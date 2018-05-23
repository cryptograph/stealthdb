#pragma once
#include "tools/sync_utils.hpp"
#include <stdlib.h>

struct request
{
    static const int max_buffer_size = 65536;
    int ocall_index;
    unsigned char buffer[max_buffer_size];
    volatile int is_done;
    int resp;
};

class Queue
{
   public:
    Queue();
    virtual ~Queue();
    int enqueue(request* elem);
    request* dequeue();
    int front, rear;

   private:
    static const int queue_size = 1024000;
    request* q[queue_size];
    int volatile _lock;
};
