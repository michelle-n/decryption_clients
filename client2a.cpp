#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <vector>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <error.h>

#include <pthread.h>

#include "constants.h"

unsigned char common_chars[] = {
        32,
        101,
        116,
        97,
        111,
        105,
        110,
        115,
        104,
        114,
        100,
        108,
        117,
        99,
        119,
        109,
        102,
        103,
        121,
        112,
        98,
        44,
        46,
        118,
        107,
        39,
        45,
        84,
        73,
        66,
        87,
        72,
        80,
        65,
        120,
        79,
        83,
        70,
        69,
        113,
        151,
        63,
        78,
        49,
        106,
        122,
        89,
        77,
        33,
        57,
        56,
        67,
        52,
        58,
        76,
        82,
        68,
        59,
        74,
        71,
        85,
        51,
        48,
        75,
        34,
        50,
        54,
        86,
        41,
        40,
        53,
        55,
        81,
        47,
        90,
        93,
        91,
        94,
        35,
        36,
        37,
        38,
        42,
        43,
        60,
        61,
        62,
        64,
        88,
        92,
        95,
        96,
        123,
        124,
        125,
        126,
        127
};

ssize_t bytes_read; 
unsigned char ctbuf[IVLEN + MACLEN + CTLEN] = { '\0' };
unsigned char ptbuf[IVLEN + MACLEN + CTLEN] = { '\0' }; // NOTE: ptbuffer should be 16+32 less

unsigned char query_oracle(unsigned char ctbuf[], size_t ctlen, int ifd[2], int ofd[2])
{
    int status;
    pid_t pid = fork();
    if (pid == 0)
    {
        // this is the child; it will simply exec into our desired
        // oracle program, but first it replaces stdin and stdout with
        // the provided pipes so that the parent can both write to
        // and read from it
        dup2(ofd[0], STDIN_FILENO);
        dup2(ifd[1], STDOUT_FILENO);

        // ask kernel to deliver SIGTERM in case the parent dies
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        // run the oracle
        execl(ORACLE, ORACLE, (char *)NULL);
        // we'll never get here, unless execl fails for some reason
	perror("execl");
        exit(1);
    }
    else
    {
	// tell the oracle how long of a ciphertext to expect
        ssize_t bytes_written = write(ofd[1], &ctlen, sizeof(ctlen));
	if (bytes_written != sizeof(ctlen)) error(1, errno, "writing ciphertext length");
	// and then write that many bytes
        bytes_written = write(ofd[1], ctbuf, ctlen);
	if (bytes_written != ctlen) error(1, errno, "writing ciphertext");
	// printf("Wrote %lu bytes of ciphertext\n", bytes_written);
	// now fetch the response
        unsigned char result = 0;
        ssize_t bytes_read = read(ifd[0], &result, sizeof(char));
	// printf("Oracle responded: %c\n", result);
	// reap the execl'd child before we return
        waitpid(pid, &status, 0);
        return result;
    }
}


void * thread_routine(void * thread_id) {

        // create some pipes for directional communication with the child process
        int ifd[2], ofd[2];
        if (pipe(ifd) != 0) error(1, errno, "creating input pipe");
        if (pipe(ofd) != 0) error(1, errno, "creating output pipe");

        // get bytes red and ciphertext len
        int64_t local_bytes_read = bytes_read;
        size_t ctlen = local_bytes_read; // NOTE: might not need like this

        // keep track of which block the thread will work on, if it was assigned any
        // initially the block the thread computes is its thread id
        int64_t thread_block = (int64_t)thread_id;
        bool assigned_block = true;

        // Make a buffer for storing the reference local ciphertext
        unsigned char reference_ct[IVLEN + MACLEN + CTLEN];
        for(int i=0; i < (IVLEN + MACLEN + CTLEN); i++){
                reference_ct[i] = ctbuf[i];
        }

        // Make a buffer for storing the altered ciphertext, initilize to be the ciphertext 
        unsigned char altered_ct[IVLEN + MACLEN + CTLEN];
        for(int i=0; i < (IVLEN + MACLEN + CTLEN); i++){
                altered_ct[i] = reference_ct[i];
        }

        // Find the padding number
        int padding;


        // reset padding
        padding = 1;

        /***************************************************/
        /***************************************************/
        /** CASE 1: BLOCK IS AT THE END OF THE CIPHERTEXT **/
        /***************************************************/
        /***************************************************/
        // for block at end of ciphertext, need to find the original plaintext (0 to 16) instead of plaintext
        if (thread_block == 0){
                
                int cipher_padding = 1;
                // Figure out the padding at the end of the ciphertext. It should be a number between 1 and 16. 
                for (int padding_number = 2; padding_number <= 16; padding_number++){
                        // Find out padding number
                        unsigned char XORkey = padding_number^1;

                        // Make an altered ciphertext 
                        altered_ct[local_bytes_read-padding-((thread_block+1)*BLOCKLEN)] = reference_ct[local_bytes_read-padding-((thread_block+1)*BLOCKLEN)]^XORkey;

                        // Query oracle. If it returns M or O, then we found the padding number. 
                        char test_result = query_oracle(altered_ct, ctlen, ifd, ofd);
                        if (test_result == 'M' || test_result == 'O'){
                                padding = padding_number;
                                cipher_padding = padding_number;
                                break;
                        }
                }
                // Now either padding was 1 or X from 2 to 16. 
                // So let's try the next padding number. 
                padding++;
                // Look for the next letters. 
                while (padding <= BLOCKLEN){

                        // Start by updating altered ciphertext to the next padding number, up to the first byte of the padding
                        for(int i = 1; i<=cipher_padding; i++){
                                altered_ct[local_bytes_read-i-((thread_block+1)*BLOCKLEN)] = reference_ct[local_bytes_read-i-((thread_block+1)*BLOCKLEN)]^cipher_padding^padding;
                        }
                        for(int i=(cipher_padding+1); i < padding; i++){
                                altered_ct[local_bytes_read-i-((thread_block+1)*BLOCKLEN)] = reference_ct[local_bytes_read-i-((thread_block+1)*BLOCKLEN)]^ptbuf[local_bytes_read-(IVLEN + MACLEN)-i-(thread_block*BLOCKLEN)]^padding;
                        }

                        for (int common_index = 0; common_index <= 95; common_index++){
                                // Find out padding number
                                unsigned char XORkey = common_chars[common_index]^padding;

                                // Make an altered ciphertext 
                                altered_ct[local_bytes_read-padding-((thread_block+1)*BLOCKLEN)] = reference_ct[local_bytes_read-padding-((thread_block+1)*BLOCKLEN)]^XORkey;

                                // Query oracle. If it returns M or O, then we found the padding alphabet. 
                                char test_result = query_oracle(altered_ct, ctlen, ifd, ofd);
                                if (test_result == 'M' || test_result == 'O'){
                                        ptbuf[local_bytes_read-(IVLEN + MACLEN)-padding-(thread_block*BLOCKLEN)] = common_chars[common_index]; 
                                        break;
                                }
                        }

                        // Update padding so we can do this loop with the next number...
                        padding++;
                }
        
        }
        /*********************************************************/
        /*********************************************************/
        /** CASE 2: BLOCK IS *NOT* AT THE END OF THE CIPHERTEXT **/
        /*********************************************************/
        /*********************************************************/
        else {

                // Adjust the ctlen
                ctlen = local_bytes_read-(thread_block*16);


                // Figure out the blocks we're on
                while (padding <= BLOCKLEN){

                        // Start by updating altered ciphertext to the next padding number, up to the first byte of the padding
                        for(int i=1; i < padding; i++){
                                altered_ct[local_bytes_read-i-((thread_block+1)*BLOCKLEN)] = reference_ct[local_bytes_read-i-((thread_block+1)*BLOCKLEN)]^ptbuf[local_bytes_read-(IVLEN + MACLEN)-i-(thread_block*BLOCKLEN)]^padding;
                        }

                        for (int common_index = 0; common_index <= 95; common_index++){
                                // Find out padding number
                                unsigned char XORkey = common_chars[common_index]^padding;

                                // Make an altered ciphertext 
                                altered_ct[local_bytes_read-padding-((thread_block+1)*BLOCKLEN)] = reference_ct[local_bytes_read-padding-((thread_block+1)*BLOCKLEN)]^XORkey;

                                // Query oracle. If it returns M or O, then we found the padding alphabet. 
                                char test_result = query_oracle(altered_ct, ctlen, ifd, ofd);
                                if (test_result == 'M' || test_result == 'O'){
                                        ptbuf[local_bytes_read-(IVLEN + MACLEN)-padding-(thread_block*BLOCKLEN)] = common_chars[common_index]; 
                                        break;
                                }
                        }

                        // Update padding so we can do this loop with the next number...
                        padding++;
                }

        }


        // clean up the pipes
        close(ofd[0]);
        close(ofd[1]);
        close(ifd[0]);
        close(ifd[1]);

        // exit thread
        pthread_exit(0);
}

int main(int argc, char * argv[])
{

        // read the ciphertext from a file
        int ctfd = open(CTFILE, O_RDONLY);
        if (ctfd == -1) error(1, errno, "opening %s", CTFILE);
        bytes_read = read(ctfd, ctbuf, IVLEN + MACLEN + CTLEN);
        if (bytes_read <= IVLEN + MACLEN) error(1, errno, "ciphertext too short");
        close(ctfd);

        // let number of threads be the number of blocks that need to be computed
        int n_threads = (bytes_read-(IVLEN + MACLEN))/BLOCKLEN;

        // create threads
        pthread_t thread_pool[n_threads];
        for (int64_t thread_id = 0; thread_id < n_threads; thread_id++)
        {
                pthread_create(&thread_pool[thread_id], NULL, thread_routine, (void *)thread_id);
        }

        // join threads
        for (int64_t thread_id = 0; thread_id < n_threads; thread_id++)
        {
                pthread_join(thread_pool[thread_id], NULL);
        }


        // print the plaintext
        // printf("%s", ptbuf);
        fprintf(stderr, "%s", ptbuf);


        return 0;
}
