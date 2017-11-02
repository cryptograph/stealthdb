struct request
{
	int ocall_index;
	unsigned char buffer[10240];
	volatile int is_done;
	int resp;
};
