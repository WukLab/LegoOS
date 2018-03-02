#include "storage.h"
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/param.h>
#include <linux/mutex.h>
#include <linux/mm.h>

/* ------------------------------------------
 * check_permission
 * 0 : not permitted
 * > 0 : permitted
 * -1: error
 * -----------------------------------------
*/
static int check_permission(request *rq, int owner, int permission){
	if (IS_ERR(rq)){
		printk("check_permission : bad request.\n");
		return -1;		
	}
	if (rq->uid == owner){
		if(rq->flags == O_RDONLY){
			//return (permission >> 3) & READ_MASK;
			return permission & S_IRUSR;
		}
		if(rq->flags & O_WRONLY){
			//return (permission >> 3) & WRITE_MASK;
			return permission & S_IWUSR;
		}
		if (rq->flags & O_RDWR){
			//return ((permission >> 3) & (READ_MASK || WRITE_MASK));
			return ((permission & S_IRUSR)>>1) & (permission & S_IWUSR);
		}
	}

	// if the user is not the owner.
	//rq->flags == O_RDONLY is not correct, need to be changed later.
	if(rq->flags == O_RDONLY){
		//return permission & READ_MASK;
		return permission & S_IROTH;
	}
	if(rq->flags & O_WRONLY){
		//return permission & WRITE_MASK;
		return permission & S_IWOTH;
	}
	if (rq->flags & O_RDWR){
		//return permission & (READ_MASK || WRITE_MASK);
		return ((permission & S_IROTH)>>1) & (permission & S_IWOTH);
	}
	
	printk("check_permission : bad request flags. rq->flags: [%d], O_RDONLY: [%d], O_WRONLY: [%d], O_RDWR: [%d]", 
		rq->flags, O_RDONLY, O_WRONLY, O_RDWR);
	return -1;
}

/* ------------------------------------------
 * grant_access
 *
 * Grants access to all the users for the requested file.
 * grant_access one file for each call
 * grant_access should check permission for existing file.
 *
 * -----------------------------------------
*/
int grant_access (request *rq, int *metadata_entry, int *user_entry) {
	
	int i, j;
	
	struct metadata *current_filemetadata;
	current_filemetadata = global_metadata;
	
	if (unlikely(IS_ERR(rq))){
	   panic("invalid request for grant_access\n");	
	   return -EACCES;
	}
	
	
	for (i=0; i<MAX_SIZE; i++) {

		// Find the metadata of the requested file, file exist;
		if (strcmp(current_filemetadata->fileName, rq->fileName) == 0) {

			printk("grant_access: file found -> %s\n", current_filemetadata->fileName);

			// Find if the user is new;
			for (j = 0; j < MAX_USERS_ALLOWED; j++){
				if (rq->uid == current_filemetadata->users[j]){
					
					/* This is the case that user do not have the permission to access existing file */

					if (check_permission(rq, current_filemetadata->owner, current_filemetadata->permission) <= 0){
						*metadata_entry = -1;
						*user_entry = -1;
						return -EACCES;
					}

					/* This is the case that user has the permission */

					*metadata_entry = i;
					*user_entry = j;
					return 0;
				}
			}

			/* Enter here means the request file exist, but the user request access 
			 * is not in the metadata user list.
			 * This is a more common case, first need to check if the file users
			 * list is full. And also check if the user has the permission to access
			 * required file
			 */

			if (current_filemetadata->noOfUsers >= MAX_USERS_ALLOWED
				   	|| (check_permission(rq, current_filemetadata->owner, current_filemetadata->permission)) <= 0){
				*metadata_entry = -1;
				*user_entry = -1;
				return -EACCES;
			}
			
			/* Enter here means request file exist, the user is not on metadata user list,
			 * but the user has permission to access file and file user list is not full,
			 * now try to find the entry
			 */

			for (j = 0; j < MAX_USERS_ALLOWED; j++){
				// find first not used user entry;
				if (current_filemetadata->users[j] == -1){
					current_filemetadata->users[j] = rq->uid;
					current_filemetadata->noOfUsers++;
					*metadata_entry = i;
					*user_entry = j;
					return 0;
				}	
			}

		}
		current_filemetadata++;
	}

	/* Enter here means the file is not exist yet
	 * The only way that grant_access success is that O_CREAT
	 * set and metadata has an empty entry;
	 */

	if (rq->flags & O_CREAT){
		
		/* Try to find an entry of global_metadata */
		int i;
		for (i = 0; i < MAX_SIZE; i++){
			if (global_metadata[i].used == 0){

				//acquire metadata lock
				mutex_lock(&metadata_lock);
				if (global_metadata[i].used){
					/* This entry is occupied by other threads after detecting */
					mutex_unlock(&metadata_lock);
					break;
				}
				global_metadata[i].used = 1;
				global_metadata[i].users[0] = rq->uid;
				global_metadata[i].owner = rq->uid;
				global_metadata[i].permission = rq->permission;
				global_metadata[i].noOfUsers = 1;
				strcpy(global_metadata[i].fileName, rq->fileName);

				//release metadata lock
				mutex_unlock(&metadata_lock);
				update_metadata();
				*metadata_entry = i;
				*user_entry = 0;
				return 0;
			}
		}
	}

	/* Enter here means O_CREAT is not set and file is not exist
	 * not grant access
	 */

	*metadata_entry = -1;
	*user_entry = -1;
	return -ENOENT;

}

/* decrease the noOfUsers and release the entry on metadata user list
 *
 */

int yield_access(int metadata_entry, int user_entry){
	if (metadata_entry < 0 || metadata_entry >= MAX_SIZE
			|| user_entry < 0 || user_entry >= MAX_USERS_ALLOWED)
		return OP_FAILURE;

	mutex_lock(&metadata_lock);
	global_metadata[metadata_entry].noOfUsers--;
	global_metadata[metadata_entry].users[user_entry] = -1;
	if (global_metadata[metadata_entry].noOfUsers < 0){
		printk("yield_access : Error, noOfUsers < 0\n");
		return OP_FAILURE;
	}
	mutex_unlock(&metadata_lock);
	update_metadata();

	return OP_SUCCESS;
}

/* Test functions.
 * These functions are only used for test purpose.
 * Should not be invoked 
 */

/* generate a request for test*/

/* set a metadata entry to a specific value for testing */

static void set_metadata(int index, int *users, int noOfUsers, fmode_t permission,
	   	int used, int owner, char *fileName){
	mutex_lock(&metadata_lock);
	memcpy(global_metadata[index].users, users, sizeof(int)*MAX_USERS_ALLOWED);
	global_metadata[index].noOfUsers = noOfUsers;
	global_metadata[index].permission = permission;
	global_metadata[index].used = used;
	global_metadata[index].owner = owner;
	strcpy(global_metadata[index].fileName, fileName);
	mutex_unlock(&metadata_lock);
	update_metadata();
}

/* count unused entry*/
static int unused_entry(void){
	int unused = 0;
	int i;

	for (i = 0; i < MAX_SIZE; i++){
		if (global_metadata[i].used == 0){
			unused++;
		}
	}

	return unused;
}

void test_grant_yield_access(void *data) {
	
	/* test for check_permission: 
	 * after init_storage_server, metadata init
	 * grant_access for new creating files
	 */

	//only for test
	//printk_hello(NULL);
	
	request rq;
	int metadata_entry, user_entry;
	int users[2];
	//test the unused_entry
	printk("There are [%d] unused metadata entries.\n", unused_entry());
	//owner r/w, other r;
	rq = constuct_request(23, "testfile1", 0744, 0, 0, O_CREAT | O_WRONLY);
	grant_access(&rq, &metadata_entry, &user_entry);
	printk("Test O_CREAT, unused entries : [%d], metadata_entry : [%d], user_entry : [%d]\n",
			unused_entry(), metadata_entry, user_entry);
	dump_metadata();

	/* now testing for a request that O_CREAT is not set and file not exist */

	rq = constuct_request(23, "testfile2", 0744, 0, 0, O_WRONLY);
	grant_access(&rq, &metadata_entry, &user_entry);
	printk("\nTest O_CREAT is not set, unused entries : [%d], metadata_entry : [%d], user_entry : [%d]\n",
			unused_entry(), metadata_entry, user_entry);
	dump_metadata();

	/* test the case that 23 access exist file testfile1, but use O_RDWR flags
	 * The user has the permission, grant access
	 */
	rq = constuct_request(23, "testfile1", 0744, 0, 0, O_RDWR);
	grant_access(&rq, &metadata_entry, &user_entry);
	printk("\nTest O_RDWR is set, unused entries : [%d], metadata_entry : [%d], user_entry : [%d]\n",
			unused_entry(), metadata_entry, user_entry);
	dump_metadata();
	
	/* test the case that 24 access exist file testfile1 using O_RDONLY flags
	 * The user has the permission, grant access
	 */
	rq = constuct_request(24, "testfile1", 0744, 0, 0, O_RDONLY);
	grant_access(&rq, &metadata_entry, &user_entry);
	printk("\nTest 24 accessing the testfile1 using O_RDONLY, unused entries : [%d], metadata_entry : [%d], user_entry : [%d]\n",
			unused_entry(), metadata_entry, user_entry);
	printk("\ncheckpermission value is %d.\n", check_permission(&rq, 23, 0744));
	dump_metadata();

	/* test the case that 24 access exist file testfile1 using O_RDWR flags
	 * The user does not have the permission, do not grant access
	 */
	rq = constuct_request(24, "testfile1", 0744, 0, 0, O_RDWR);
	grant_access(&rq, &metadata_entry, &user_entry);
	printk("\nTest 24 accessing the testfile1 using O_RDWR, unused entries : [%d], metadata_entry : [%d], user_entry : [%d]\n",
			unused_entry(), metadata_entry, user_entry);
	dump_metadata();


	/* test the case that 24  yeild access testfile1	 
	 */
	printk("\nTest user 24 yield access testfile1\n");			;
	yield_access(metadata_entry, user_entry);
	dump_metadata();

	/* Test a complex case, assume max_size=2 and max_users_allowed=2, 23 create testfile 1 with 0744, 24 create
	 * testfile2 with 0744, and 23, 24 access file1 and file2 now, so no other user can access testfile1 and testfile2
	 * since user list is full. and no other user could create a new file since metadata list is full.
	 * Then we 24 yield_access testfile1, now 25 should be able to access testfile1 with O_RDONLY flags. 
	 *
	*/
	users[0] = 23;
	users[1] = 24;
	set_metadata(0, users, 2, 0744, 1, 23, "testfile1");
	set_metadata(1, users, 2, 0744, 1, 24, "testfile2");
	printk("\nCheck if metedata set correct before testing'\n");
	dump_metadata();

	//Now user 25 coming, test create testfile3;
	rq = constuct_request(25, "testfile3", 0744, 0, 0, O_CREAT | O_WRONLY);
	grant_access(&rq, &metadata_entry, &user_entry);
	printk("\nTest 25 creating testfile3, unused entries : [%d], metadata_entry : [%d], user_entry : [%d]\n",
			unused_entry(), metadata_entry, user_entry);
	dump_metadata();

	//test access testfile1;
	rq = constuct_request(25, "testfile1", 0744, 0, 0, O_RDONLY);
	grant_access(&rq, &metadata_entry, &user_entry);
	printk("\nTest 25 accessing testfile1, unused entries : [%d], metadata_entry : [%d], user_entry : [%d]\n",
			unused_entry(), metadata_entry, user_entry);
	dump_metadata();

	//Now 24 yield accessing file1, then 25 try to access testfile1
	yield_access(0, 1);
	grant_access(&rq, &metadata_entry, &user_entry);
	printk("\nTest 25 accessing testfile1 after 24 yield, unused entries : [%d], metadata_entry : [%d], user_entry : [%d]\n",
			unused_entry(), metadata_entry, user_entry);
	dump_metadata();
}

/* The testing functions end */
