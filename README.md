DES
===
More details can be found inside of the programs.

-------------------------------------------------------------------------------
For SEEP protocol, the programs follow the following steps:
(A: client, B: server)

0: The server and the client generate public and private keys sepertely, and then send each other its own public key.

1A: Client gets data(string) from User input(user can enter string).

2A: Client picks a nonceA (random number).

3A: Client sends request for communication(session): "req_for_session" || {nonceA} encrypted with Bpub.

4B: Server receives message decrypt with Bprivate, store NonceA.

5B: Server picks session key K, according to the random number from client and that generated in the server.

6B: Server sends message to A “new_session_key” || {K} encrypted with Apub.

7A: Client receives message and decrypts wih Aprivate and store K.

8A: Client sends message to B “ack_new_session_key” encrypted with RC6 using key K.

9A: Client sends data to B “encoded_msg_ok” || {data} encrypted with RC6 using key K.

10B: Server receives data from A, checks OK field, decodes data, and displays data to user.




For SSL Protocol, the programs follow the following steps:
(A: Client, B: Server)

1A: Client sends "hello" message with a random number and a set of available algorithms for the server to choose.

2B: Server receives "hello" message from the client.

3B: Server responses the "hello" message with another random number, and the chosen algorithm for the following communication.

4B: Server generates and sends the certificate and the public key.

5A: Client verifys the certificate using the public key.

6A: Client sends a key exchange message, including the encrypted premaster secret.

7B: Server receives and decrypts the premaster secret using private key.

8A: Client sends "handshake finish" and its corresponding hmac value.

9A: Server checks whether the hmac value from the client is correct.

10A: Server checks whether the information of "handshake finish" is correct.

11A: Server sends its "handshake finish" and its hmac value to the client.

12B: Client checks whether "handshake finish" and its hmac value from the server are correct.

Now handshake steps finish, and user can input something from the client, and the client encrypts the data and then sends them to the server.

The server receives the encrypted data and the hmac value, then checks the correctness of hmac, and at last displays the data.




About the comparison of the security, complexity and performance.

No good way to do this job. "time" command cannot work, since the total time of the programs depends on my data input speed, not the pure time of running the codes.
