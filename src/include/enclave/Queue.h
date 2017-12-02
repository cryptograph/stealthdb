#include "request.h"

class Queue {
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
