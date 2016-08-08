#Chat Server Project  
Works best on Ubuntu

Allow multiple users to chat to one another using the terminal.
The following is instructions on how to run the project and the settings available 

##Client Program##
`./client [-hcv] [-a FILE] NAME SERVER_IP SERVER_PORT`  
`-a FILE Path to the audit log file`  
`-h Displays this help menu, and returns EXIT_SUCCESS. Requests to server to create a new user`  
`-c Requests to server to create a new user`  
`-v Verbose print all incoming and outgoing protocol verbs & content.`  
`NAME: The username to display when chatting.`  
`SERVER_IP: The ipaddress of the server to connect to. The port to connect to.`   
`SERVER_PORT: The port to connect to.`  

##Chat Program##
#####This is automatically run by the client program#####
`./chat UNIX_SOCKET_FD AUDIT_FILE_FD`  
`UNIX_SOCKET_FD: The Unix Domain file descriptor number.`  
`AUDIT_FILE_FD: The file descriptor of the audit.log created in the client program.`  

##Server Program##
`./server [-hv] [-t THREAD_COUNT] PORT_NUMBER MOTD [ACCOUNTS_FILE]`  
`-h Displays help menu & returns EXIT_SUCCESS.`  
`-t THREAD_COUNT  The number of threads used for the login queue.`  
`-v Verbose print all incoming and outgoing protocol verbs & content. Port number to listen on.`  
`PORT_NUMBER: Port number to listen on`  
`MOTD: Message to display to the client when connected`  
`ACCOUNTS_FILE: File containing username and password data to be loaded upon`  

Users are created and stored in SQLite database. 
Passwords are hashed with salt for security 
Project is almost completely thread-safe but it is for the most part :sweat_smile:
