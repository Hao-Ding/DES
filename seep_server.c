#include <errno.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <sys/socket.h>  
#include <sys/wait.h>  
#include <arpa/inet.h>  
#include <unistd.h>  
#include <tomcrypt.h>

#define SERVPORT 3333  
#define BACKLOG 10  
#define MAXSIZE 1024  

/* Initialize for socket communication as a server */
int init(struct sockaddr_in *serv_addr){
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket create failed!");
        exit(1);
    }
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(SERVPORT);
    serv_addr->sin_addr.s_addr = INADDR_ANY;
    bzero(&(serv_addr->sin_zero), 8);
    if (bind(sock, (struct sockaddr*) serv_addr, sizeof(struct sockaddr))== -1) {
        perror("bind error!");
        exit(1);
    }
    if (listen(sock, BACKLOG) == -1) {
        perror("listen error");
        exit(1);
    }
    return sock;
}

/* Initialize for rsa */
int init_for_rsa(int *hash_idx, int *prng_idx, prng_state *prng) {
    int err;
    if (register_hash(&sha1_desc) == -1) {
        printf("Error registering sha1");
        return -1;
    }
    if (register_prng(&rc4_desc) == -1) {
        printf("Error registering Yarrow\n");
        return -1;
    }
    if (((*hash_idx) = find_hash("sha1")) == -1 || ((*prng_idx) = find_prng("rc4")) == -1) {
        printf("hash_idx = %d\nprng_idx = %d\n", *hash_idx, *prng_idx);
        printf("rsa_test requires LTC_SHA1 and rc4\n");
        return -1;
    }
    if ((err = rng_make_prng(128, find_prng("rc4"), prng, NULL)) != CRYPT_OK) {
        printf("Error rng_make_prng: %s\n", error_to_string(err));
        return -1;
    }
    return 0;
}

/* Receive public key of client(Apub) */
int serv_recv_pub_key(int client_fd, unsigned char pub_key_from_cli[], unsigned long *pub_key_from_cli_len) {
    read(client_fd, pub_key_from_cli_len, sizeof(int));
    read(client_fd, pub_key_from_cli, *pub_key_from_cli_len);
    return 0;
}

/* Generate Bpub and Bprivate and send Bpub to the client */
int serv_gen_and_send_key(int client_fd, prng_state prng, int prng_idx, unsigned char pub_key_for_out[], unsigned char pri_key_for_out[], unsigned long pub_len, unsigned long pri_len) {
    rsa_key key1;
    int err;

    if ((err = rsa_make_key(&prng, prng_idx, 1024/8, 65537, &key1)) !=CRYPT_OK) {
        printf("Error rsa_make_key: %s\n", error_to_string(err));
        return -1;
    }
    /* Server creates public key and private key (pub_key_for_out[] is the string to store the public key to be sent to the client, while pub_key and pri_key are the rsa_key type data, which store the public key and private key inside of the server)*/
    if ((err = rsa_export(pub_key_for_out, &pub_len, PK_PUBLIC, &key1)) != CRYPT_OK) {
        printf("Error rsa_export public: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = rsa_export(pri_key_for_out, &pri_len, PK_PRIVATE, &key1)) != CRYPT_OK) {
        printf("Error rsa_export private: %s\n", error_to_string(err));
        return -1;
    }
    
    /* Server sends the public key */
    send(client_fd, &pub_len, sizeof(int), 0);
    send(client_fd, pub_key_for_out, pub_len, 0);
}

/* Receive and decrypt "req_for_session" || {nonceA} */
int serv_recv_and_decrypt_req_for_session(int client_fd, int hash_idx, unsigned char pri_key_for_out[], unsigned long pri_key_for_out_len, unsigned char cli_rand[]) {
    /* Server receives encrypted "req_for_session" message and hmac from client */
    unsigned char data_string[] = "req_for_session";
    unsigned char data_before_decrypt[1024], data_after_decrypt[32], rand_before_decrypt[1024], rand_after_decrypt[28];
    unsigned long data_before_decrypt_len, rand_before_decrypt_len;
    
    memset(data_before_decrypt, 0, 1024);
    memset(data_after_decrypt, 0, 32);
    memset(rand_before_decrypt, 0, 1024);
    memset(rand_after_decrypt, 0, 28);

    read(client_fd, &data_before_decrypt_len, sizeof(int));
    read(client_fd, data_before_decrypt, data_before_decrypt_len);
    read(client_fd, &rand_before_decrypt_len, sizeof(int));
    read(client_fd, rand_before_decrypt, rand_before_decrypt_len);

    /* Server decrypts "req_for_session" from client and checks it*/
    rsa_key pri_key;
    int err;
    if ((err = rsa_import(pri_key_for_out, pri_key_for_out_len, &pri_key)) != CRYPT_OK) {
        printf("Error rsa_import public: %s\n", error_to_string(err));
        return -1;
    }
    int stat1, stat2;
    unsigned long data_after_decrypt_len = sizeof(data_after_decrypt);
    if ((err = rsa_decrypt_key(data_before_decrypt, data_before_decrypt_len, data_after_decrypt, &data_after_decrypt_len, NULL, 0, hash_idx, &stat1, &pri_key)) != CRYPT_OK) {
        printf("Error rsa_decrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    if (strcmp(data_after_decrypt, "req_for_session") == 0) {
        printf("Receive \"req_for_session\".\n");
    }
    else {
        printf("Error when receive \"req_for_session\" and stop. \n");
        exit(1);
    }

    unsigned long rand_after_decrypt_len = sizeof(rand_after_decrypt);
    if ((err = rsa_decrypt_key(rand_before_decrypt, rand_before_decrypt_len, rand_after_decrypt, &rand_after_decrypt_len, NULL, 0, hash_idx, &stat2, &pri_key)) != CRYPT_OK) {
        printf("Error rsa_decrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    strcpy(cli_rand, rand_after_decrypt);
//    printf("Rand after decrypt=%s\n", rand_after_decrypt);
    return 0;
}

/* Generate new session key according to the random number both from the client and picked in the server */
int serv_gen_session_key(unsigned char cli_rand[], unsigned char serv_rand[], unsigned char ses_key[]) {
    prng_state prng;
    int i, err;
    unsigned char total_rand[56];
    for (i = 0; i < 28; i++) {
        total_rand[i] = cli_rand[i];
        total_rand[i+28] = serv_rand[i];
    }
    if ((err = yarrow_start(&prng)) != CRYPT_OK) {
        printf("Start error: %s\n", error_to_string(err));
    }
    if ((err = yarrow_add_entropy(total_rand, 56, &prng)) != CRYPT_OK) {
        printf("Add_entropy error: %s\n", error_to_string(err));
    }
    if ((err = yarrow_ready(&prng)) != CRYPT_OK) {
        printf("Ready error: %s\n", error_to_string(err));
    }
    yarrow_read(ses_key, 16, &prng);
    return 0;
}

/* Send "new_session_key" || {K}, encrypted with Apub */
int serv_send_new_session_key(int client_fd, prng_state prng, int hash_idx, int prng_idx, unsigned char ses_key[], unsigned char pub_key_from_cli[], unsigned long pub_key_from_cli_len) {
    rsa_key pub_key_cli;
    int err;
    if ((err = rsa_import(pub_key_from_cli, pub_key_from_cli_len, &pub_key_cli)) != CRYPT_OK) {
        printf("Error rsa_import public: %s\n", error_to_string(err));
        return -1;
    }
    
    /* Encrypt "new_session_key" */
    unsigned char msg_before_encrypt[] = "new_session_key";
    unsigned char msg_after_encrypt[1024];
    memset(msg_after_encrypt, 0, 1024);
    unsigned long msg_after_encrypt_len = sizeof(msg_after_encrypt);
    if ((err = rsa_encrypt_key(msg_before_encrypt, sizeof(msg_before_encrypt), msg_after_encrypt, &msg_after_encrypt_len, NULL, 0, &prng, prng_idx, hash_idx, &pub_key_cli)) !=CRYPT_OK ) {
        printf("Error rsa_encrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    send(client_fd, &msg_after_encrypt_len, sizeof(int), 0);
    send(client_fd, msg_after_encrypt, msg_after_encrypt_len, 0);

    /* Encrypt K */
    unsigned char ses_key_after_encrypt[1024];
    memset(ses_key_after_encrypt, 0, 1024);
    unsigned long ses_key_after_encrypt_len = sizeof(ses_key_after_encrypt);
    if ((err = rsa_encrypt_key(ses_key, 16, ses_key_after_encrypt, &ses_key_after_encrypt_len, NULL, 0, &prng, prng_idx, hash_idx, &pub_key_cli)) !=CRYPT_OK ) {
        printf("Error rsa_encrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    send(client_fd, &ses_key_after_encrypt_len, sizeof(int), 0);
    send(client_fd, ses_key_after_encrypt, ses_key_after_encrypt_len, 0);
    return 0;
}

/* Receive, decode and display data from A */
int serv_recv_data_and_display(int client_fd, unsigned char ses_key[]) {
    unsigned char msg_ack[1024], msg_encoded[1024], msg_data[1024];
    unsigned char msg_ack_after_decrypt[1024], msg_encoded_after_decrypt[1024], msg_data_after_decrypt[1024];
    unsigned long msg_ack_len;
    symmetric_CTR ctr;
    unsigned char IV[16];
    int err;

    memset(IV, 0, 16);
    memset(msg_ack, 0, 1024);

    read(client_fd, msg_ack, 1024);
    read(client_fd, msg_encoded, 1024);
    read(client_fd, msg_data, 1024);

    if (register_cipher(&rc6_desc) == -1) {
        printf("Error registering cipher.\n");
        return -1;
    }
    if ((err = ctr_start(find_cipher("rc6"), IV, ses_key, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
        printf("ctr_start error: %s\n", error_to_string(err));
        return -1;
    }

    /* Decrypt and check "ack_new_session_key" */
    if ((err = ctr_decrypt(msg_ack, msg_ack_after_decrypt, 1024, &ctr)) != CRYPT_OK) {
        printf("ctr_decrypt error: %s\n", error_to_string(err));
        return -1;
    }
    if (strcmp(msg_ack_after_decrypt, "ack_new_session_key") == 0) {
        printf("Receive \"ack_new_session_key\"\n");
    }
    else {
        printf("Error when receive \"ack_new_session_key\" and stop\n");
        exit(1);
    }

    /* Decrypt and check "encoded_msg_ok" */
    if ((err = ctr_setiv(IV, 16, &ctr)) != CRYPT_OK) {
        printf("ctr_setiv error: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_decrypt(msg_encoded, msg_encoded_after_decrypt, 1024, &ctr)) != CRYPT_OK) {
        printf("ctr_decrypt error: %s\n", error_to_string(err));
        return -1;
    }
    if (strcmp(msg_encoded_after_decrypt, "encoded_msg_ok") == 0) {
        printf("Receive \"encoded_msg_ok\"\n");
    }
    else {
        printf("Error when receive \"encoded_msg_ok\" and stop\n");
        exit(1);
    }
    
    /* Decrypt and display data */
    if ((err = ctr_setiv(IV, 16, &ctr)) != CRYPT_OK) {
        printf("ctr_setiv error: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_decrypt(msg_data, msg_data_after_decrypt, 1024, &ctr)) != CRYPT_OK) {
        printf("ctr_decrypt error: %s\n", error_to_string(err));
        return -1;
    }
    printf("\nData from client: %s\n", msg_data_after_decrypt);
    return 0;
}

int main() {  
    ltc_mp = ltm_desc;
    int sockfd, client_fd;  
    struct sockaddr_in my_addr;  
    struct sockaddr_in remote_addr;  

    /* Server initializes the socket connection*/
    sockfd = init(&my_addr);
    while (1) {  
        socklen_t sin_size = sizeof(struct sockaddr_in);  
        if ((client_fd = accept(sockfd,(struct sockaddr*) &remote_addr,&sin_size)) == -1){  
            perror("accept error!");  
            continue;  
        }  
        printf("Received a connection from %s\n", (char*)inet_ntoa(remote_addr.sin_addr));  

        if (!fork()){ 
            /* Server initializes for rsa*/           
            int hash_idx, prng_idx;
            prng_state prng;
            init_for_rsa(&hash_idx, &prng_idx, &prng);   
            
            /* Server receives client's public key */
            unsigned char pub_key_from_cli[1024];
            unsigned long pub_key_from_cli_len = sizeof(pub_key_from_cli)-1; 
            memset(pub_key_from_cli, 0, 1024);
            serv_recv_pub_key(client_fd, pub_key_from_cli, &pub_key_from_cli_len);

            /* Server generates its public and private keys and sends public key */
            unsigned char pub_key_for_out[1024], pri_key_for_out[1024];
            unsigned long pub_len=sizeof(pub_key_for_out)-1;
            unsigned long pri_len=sizeof(pri_key_for_out)-1;
            memset(pub_key_for_out, 0, 1024);
            serv_gen_and_send_key(client_fd, prng, prng_idx, pub_key_for_out, pri_key_for_out, pub_len, pri_len);

            /* 4B: Server receives, decrypts "req_for_session" || {nonceA}, and stores NonceA */
            unsigned char cli_rand[28];
            serv_recv_and_decrypt_req_for_session(client_fd, hash_idx, pri_key_for_out, pri_len, cli_rand);

            /* 5B: Server picks session key(random number) */
            unsigned char serv_rand[28];
            unsigned char ses_key[16];
            rng_get_bytes(serv_rand, 28, NULL);
//            printf("Rand: %s\n", serv_rand);
            serv_gen_session_key(cli_rand, serv_rand, ses_key);
            

            /* 6B: Server sends encrypted “new_session_key” || {K} */
            serv_send_new_session_key(client_fd, prng, hash_idx, prng_idx, ses_key, pub_key_from_cli, pub_key_from_cli_len);

            /* 10B: Server receives, decodes, checks data and displays them */
            serv_recv_data_and_display(client_fd, ses_key);

            close(client_fd);  
            exit(0);  
        }  
        close(client_fd);  
    }  
    return 0;  
}
