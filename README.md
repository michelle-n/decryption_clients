# decryption_clients

Code for a security course to decrypt some message with the help of an oracle. 

One of the 5 people in a class of 111 students to 'beat' the expected time, did so by:
- multithreading the decryption of ciphertext blocks
- optimizing the order characters are checked using an English alphabet frequency table

Although at some point I implemented barriers for thread reuse, it was counterproductive for the size of the messages. 

I am thinking that I might code the oracle at some point and maybe clean up the code for the clients. #todo
