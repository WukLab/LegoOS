/*
 * Test execv() SYSCALL
 */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
        char *fname = "/usr/bin/python";
        char * const argv[] = { 
                fname,
                "/root/yutong/model/models-1.4.0/official/mnist/mnist.py",
		"--train_epochs",
		"1",
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
