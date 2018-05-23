#include "enclave/Queue.hpp"

Queue::Queue()
{
    front = rear = 0;
    for (int i = 0; i < queue_size; i++)
    {
        q[i] = NULL;
    }
}

Queue::~Queue() {}

int Queue::enqueue(request* elem)
{
    spin_lock(&_lock);

    if (rear - front == queue_size)
    {
        spin_unlock(&_lock);
        abort();
        return -1;
    }

    q[rear % queue_size] = elem;
    ++rear;

    spin_unlock(&_lock);
    return 0;
}

request*
Queue::dequeue()
{
    spin_lock(&_lock);

    if (front == rear)
    {
        spin_unlock(&_lock);
        return NULL;
    }

    request* result = q[front % queue_size];
    ++front;
    spin_unlock(&_lock);

    return result;
}
