/*
 * Test execv() SYSCALL
 */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
        char *fname = "/root/yutong/phoenix/phoenix-2.0/tests/word_count/word_count-seq";
        char * const argv[] = { 
                fname,
                "/root/yutong/phoenix/phoenix-2.0/tests/word_count/word_count_datafiles/word_1GB.txt",
                NULL,
        };  

        setbuf(stdout, NULL);
        printf("Before execv\n");

        if (!fork()){
                execv(fname, argv);
                printf("BUG!\n");
                return 0;
        } else
                wait(NULL);

        printf("After execv\n");

        return 0;
}
