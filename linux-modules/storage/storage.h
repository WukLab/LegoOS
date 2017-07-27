#include <linux/fs.h>
#include <linux/mutex.h>

#define OP_SUCCESS		1
#define OP_FAILURE		0


#define MAX_USERS_ALLOWED 	2
#define MAX_FILE_NAME		256

#define READ_MASK  		0x1
#define WRITE_MASK 		0x2
#define EXECUTABLE_MASK 	0x4

#define FILE_METADATA		"/home/yilun/file_metadata.bin"
#define FILE_REPO		"/data/0/file_repository/"

#define MAX_SIZE		2 


struct metadata {
	int		users[MAX_USERS_ALLOWED]; // Users who have access to this file
	int	        noOfUsers;	// No of users accessing this file currently 
	int 		permission; // The file permission applicable to all the users
	int 		used;			// File descriptor
	int		owner;
	char 		fileName[MAX_FILE_NAME];  	
};

typedef struct {
	// userID, fileName, service, length, offset, requesterInfo?, flags 
	int  	uid;
	char 	fileName[MAX_FILE_NAME]; // Requested file
	int 	service; // Specifies the read/write/update/create service requested
	int 	permission; // Permission for the data
	int 	len; 
	int 	offset;
	int 	flags;
} request;

/* init.c */
extern struct metadata global_metadata[MAX_SIZE];
extern struct mutex metadata_lock;

/* metadata.c */
int get_metadata(void);
int update_metadata(void);
void dump_metadata(void);

/* permission.c */
int grant_access (request *, int *, int *);
int yield_access(int, int);
void test_grant_yield_access(void *);

/* file_ops.c */
struct file *local_file_open (request *);
int local_file_close(struct file *);
ssize_t local_file_write(struct file *, const char __user *, ssize_t, loff_t *);
ssize_t local_file_read(struct file *, const char __user *, ssize_t, loff_t *);
int local_fsync(struct file *);

/* handler.c */
int handle_fake_read(void *);
