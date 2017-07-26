/*****
Author  : Sumukh Hallymysore Ravindra
Date    : Mar 2, 2017
Purpose : Header file 
******/

//#include "stdio.h"
//#include "stdlib.h"
#include <linux/fs.h>

#define OP_SUCCESS		1
#define OP_FAILURE		0
//This is the return value of grant_access while O_CREAT is set and file not exist.
#define NEW_FILE		2

#define MAX_USERS_ALLOWED 	2
#define MAX_FILE_NAME		20
#define ROOT_PRIVILEGE		S_IRWXU

#define READ_MASK  		0x1
#define WRITE_MASK 		0x2
#define EXECUTABLE_MASK 	0x4

#define FILE_METADATA		"/home/yilun/file_metadata.bin"
#define FILE_REPO		"/data/0/file_repository/"

#define EMETAFULL		-1

#define MAX_SIZE		2 

struct userDetails {
	int   	userID; 	// The unique identifier for the user 
	int  	permission; // Access permission for the user for the particular file
};

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

// wrapper for request information and the data sent to write
typedef struct {
	request *rq;
	char *buf;
} parsedRequest;

//void *requestHandler (void *rq);	// Each child process calls the handle request function to pase the request and reply
//int firstTimeInit ();
//extern int init_storage_server();
//void testCase();
//int fileOpen (request *rq, int *fd); 	// If requested for open, reset the offset to the beginning?
//int fileClose (int fd);
//int fileRead (request *rq, int fd, void *buf); 	// Read len bytes from the file starting at the offset maintained in the fileMetadata for the particular user
//int fileWrite (request *rq, int fd, void *buf);  	// Write data to the file storage
//int grantAccess (request *rq, struct userDetails *user, int noOfUsers); 

//userDetails * addUser (request *rq, metaData *file); // Add the user to the access list for the particular file

// api to provide the funcitonalty of updating the metadata for list of users *(grant permission) 
// flags
//if flush is set, fsync. Update the metadata.  
// corner cases
/*

What if two requests with same name for create come?
What if two write happen on the same file from two distinct processes

*/ 
