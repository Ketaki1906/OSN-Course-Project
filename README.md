# Network File System
## Operating Systems and Networks - Course Project

### About the Project 
The project is to implement a simple network (or rather, a distributed) file system from scratch. It consists of three major component -
- Clients: Clients represent the systems or users requesting access to files within the network file system.
- Naming Server: The Naming Server stands as a pivotal component in the NFS architecture. This singular instance serves as a central hub, orchestrating communication between clients and the storage servers.
- Storage Servers: Storage Servers form the foundation of the NFS. These servers are responsible for the physical storage and retrieval of files and folders. 

The client gets to implement the following operations -
1. Copy Files
2. Create or Delete Files/Folders
3. Read a file
4. Write to a file
5. Get File Permission and Size
6. Stream a Audio File
7. List all Accessible Paths
8. Exit

The program is capable of handling multiple clients concurrently by using the concept of threads and locks. Any number of clients can read a given file at a particular moment, however only 1 client is allowed to write in a file at the same time. In order to count for the time complexity and improve the efficiency of the system, we have an integrated tries that gives us an O(const) complexity to search for the server details. To further improve the performance, there is a implementation of a cache named LRU that stores the details of the recent searches, which helps in reducing any unnecessary search and thereby improving the run time. 

### Assumptions 
- Directory names end with '/' (even when the user wants to create a new directory).
- If the user wants to create a file 'abc.txt' in dir1 then dir1 should already exist. The user cannot create 'dir1/abc.txt' at once.
- In order to delete a directory, the user first deletes all the content inside it.
- The paths provided by the storage server while registering are correct and exist.
- All paths across all the storage servers are unique. 
- All the destination paths should end with '/' for copy.
- The copy function copies only the files and not the directories (present in the directories). 

### Team No. - 18
- Ayush Sahu (2022113003)
- Gargi Shroff (2022114009)
- Ketaki Shetye (2022114013)
- Rahul Singal (2022113009)