# define MAX_PATH FILENAME_MAX

#include "untrusted/interface/stdafx.h"
#include "untrusted/interface/interface.h"
#include <fstream>
#include <algorithm>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

uint8_t INPUT_BUFFER[INPUT_BUFFER_SIZE];
uint8_t OUTPUT_BUFFER[INPUT_BUFFER_SIZE];
Queue* inQueue;
bool status = false;

int launch_enclave(sgx_launch_token_t* token, int *updated)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	ret = sgx_create_enclave(ENCLAVE_FILENAME, TRUE, token, updated, &global_eid, NULL);
	if(ret != SGX_SUCCESS)
		return ret;
	else
		return 0;

}

int init()
	{
		sgx_launch_token_t token = {0};
		int updated = 0;
		int resp = launch_enclave(&token, &updated);

		return resp;
	}

//void *enclaveThread(void *) {
void enclaveThread() {
	int resp = 0;
	int ans = enclaveProcess(global_eid, &resp, inQueue);

}
int initMultithreading()
	{
		sgx_launch_token_t token = {0};
		int updated = 0;
		//pthread_t th;
		status = true;
		int ans = launch_enclave(&token, &updated);

		inQueue = new Queue();

		for(int i = 0; i < INPUT_BUFFER_SIZE; i++)
			INPUT_BUFFER[i] = OUTPUT_BUFFER[i] = 0;

		//pthread_create(&th, NULL, &enclaveThread, NULL);
		//pthread_detach(th);

		std::thread th = std::thread(&enclaveThread);

		//std::vector<std::thread> threads;
		//threads.push_back(std::thread(&enclaveThread));

		//SetThreadPriority(&th, 31);
		th.detach();

		//for (auto& th : threads) th.detach();

		return ans;
	}


int generateKey()
{
	if (!status) {
		int resp = initMultithreading();
	//	return resp;//IS_NOT_INITIALIZE;
	}

	sgx_launch_token_t token = {0};
	int updated = 0;
	int resp, resp_enclave, flength ;
	uint8_t *sealed_key_b = new uint8_t[SEALED_KEY_LENGTH];
	//std::array<BYTE, SEALED_KEY_LENGTH> sealed_key;

	std::fstream data_file;
	data_file.open(DATA_FILENAME, std::fstream::in | std::fstream::out | std::fstream::binary);
	if (data_file)
	{
		data_file.seekg (0, data_file.end);
		flength = data_file.tellg();

		if (flength == SEALED_KEY_LENGTH)
			return 0;

		else {
			resp = generateKeyEnclave(global_eid, &resp_enclave, sealed_key_b, SEALED_KEY_LENGTH);
			if(resp != SGX_SUCCESS)
				return resp;
			data_file.write((char *)sealed_key_b, SEALED_KEY_LENGTH);
		}
	}
	else
		return NO_KEYS_STORAGE;

	data_file.close();
	delete[] sealed_key_b;

	return (int)flength/SEALED_KEY_LENGTH;
}


int loadKey(int item)
{
	if (!status) {
		int resp = initMultithreading();
	//	return resp;//IS_NOT_INITIALIZE;
	}
	sgx_launch_token_t token = {0};
	int updated = 0;
	int resp, resp_enclave;
	uint8_t sealed_key_b[SEALED_KEY_LENGTH];
	//std::array<BYTE, SEALED_KEY_LENGTH> sealed_key;

	std::fstream data_file;
	data_file.open(DATA_FILENAME, std::fstream::in | std::fstream::binary);
	if (data_file)
	{
		data_file.seekg (0, data_file.end);
		int flength = data_file.tellg();
		if (flength < item*SEALED_KEY_LENGTH + SEALED_KEY_LENGTH)
			return NO_KEY_ID;

		data_file.seekg (item*SEALED_KEY_LENGTH);
		data_file.read((char *)sealed_key_b, SEALED_KEY_LENGTH);
		resp = loadKeyEnclave(global_eid, &resp_enclave, sealed_key_b, SEALED_KEY_LENGTH);
		if(resp != SGX_SUCCESS)
			return resp;
	}
	else
		return NO_KEYS_STORAGE;

	data_file.close();
	return 0;
}
