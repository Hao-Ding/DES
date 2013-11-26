#include <errno.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <sys/socket.h>  
#include <sys/wait.h>  
#include <arpa/inet.h>  
#include <unistd.h>  
#include <tomcrypt.h>

#define SERVPORT 3333  
#define SERVER_IP "127.0.0.1"  

/* Initialize for basic socket communication as a client*/
int init(struct sockaddr_in *serv_addr){
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) { 
        perror("socket error!"); 
        exit(1); 
    } 
    bzero(serv_addr, sizeof(struct sockaddr_in)); 
    serv_addr->sin_family = AF_INET; 
    serv_addr->sin_port = htons(SERVPORT); 
    serv_addr->sin_addr.s_addr = inet_addr(SERVER_IP); 

    if (connect(sock, (struct sockaddr *)serv_addr, sizeof(struct sockaddr))== -1) { 
        perror("connect error!"); 
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
    if (register_prng(&yarrow_desc) == -1) {
        printf("Error registering Yarrow\n");
        return -1;
    }
    if (((*hash_idx) = find_hash("sha1")) == -1 || ((*prng_idx) = find_prng("yarrow")) == -1) {
        printf("hash_idx = %d\nprng_idx = %d\n", *hash_idx, *prng_idx);
        printf("rsa_test requires LTC_SHA1 and yarrow\n");
        return -1;
    }
    if ((err = rng_make_prng(128, find_prng("yarrow"), prng, NULL)) != CRYPT_OK) {
        printf("Error rng_make_prng: %s\n", error_to_string(err));
        return -1;
    }
    return 0;
}

/* Generate client Apub and Aprivate, and send Apub to the server(B) */
int cli_gen_and_send_key(int sock, prng_state prng, int prng_idx, unsigned char pub_key_for_out[], unsigned char pri_key_for_out[], unsigned long pub_len, unsigned long pri_len) {
    rsa_key key1;
    int err;

    if ((err = rsa_make_key(&prng, prng_idx, 1024/8, 65537, &key1)) !=CRYPT_OK) {
        printf("Error rsa_make_key: %s\n", error_to_string(err));
        return -1;
    }
    /* Client creates public key and private key (pub_key_for_out[] is the string to store the public key to be sent to the server, while pub_key and pri_key are the rsa_key type data, which store the public key and private key inside of the client)*/
    if ((err = rsa_export(pub_key_for_out, &pub_len, PK_PUBLIC, &key1)) != CRYPT_OK) {
        printf("Error rsa_export public: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = rsa_export(pri_key_for_out, &pri_len, PK_PRIVATE, &key1)) != CRYPT_OK) {
        printf("Error rsa_export private: %s\n", error_to_string(err));
        return -1;
    }
    
    /* Client sends the public key */
    write(sock, &pub_len, sizeof(int));
    write(sock, pub_key_for_out, pub_len);
}

/* Receive Bpub from the server */
int cli_recv_pub_key(int sock, unsigned char pub_key_from_serv[], unsigned long *pub_key_from_serv_len) {
    recv(sock, (void *)pub_key_from_serv_len, sizeof(int), 0);
    recv(sock, (void *)pub_key_from_serv, *pub_key_from_serv_len, 0);
    return 0;
}

/* Get data from user input */
int cli_get_data_from_user(unsigned char data_string[]) {
    printf("Please input data(less than 1024 bytes): ");
    int i = 0;
    do {
        scanf("%c", &data_string[i]);
        i++;
    } while(data_string[i-1] != '\n');
    return 0;
}

/* Send "req_for_session" || {nonceA} to B */
int cli_send_req_for_session(int sock, prng_state prng, int hash_idx, int prng_idx, unsigned char cli_rand[], unsigned char pub_key_from_serv[], unsigned long pub_key_from_serv_len) {
    unsigned char data_string[32], data_after_encrypt[1024], rand_after_encrypt[1024];
    unsigned long data_after_encrypt_len, rand_after_encrypt_len;
    rsa_key pub_key_serv;
    int err;

    memset(data_string, 0, 32);

    strcpy(data_string, "req_for_session");
    if ((err = rsa_import(pub_key_from_serv, pub_key_from_serv_len, &pub_key_serv)) != CRYPT_OK) {
        printf("Error rsa_import public: %s\n", error_to_string(err));
        return -1;
    }
    data_after_encrypt_len = sizeof(data_after_encrypt);
    if ((err = rsa_encrypt_key(data_string, sizeof(data_string), data_after_encrypt, &data_after_encrypt_len, NULL, 0, &prng, prng_idx, hash_idx, &pub_key_serv)) !=CRYPT_OK ) {
        printf("Error rsa_encrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    
    write(sock, &data_after_encrypt_len, sizeof(int));
    write(sock, data_after_encrypt, data_after_encrypt_len);

    rand_after_encrypt_len = sizeof(rand_after_encrypt);
    if ((err = rsa_encrypt_key(cli_rand, 28, rand_after_encrypt, &rand_after_encrypt_len, NULL, 0, &prng, prng_idx, hash_idx, &pub_key_serv)) !=CRYPT_OK ) {
        printf("Error rsa_encrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    write(sock, &rand_after_encrypt_len, sizeof(int));
    write(sock, rand_after_encrypt, rand_after_encrypt_len);
    return 0;
}

/* Receive "new_session_key" || {K}, and decrypt it to get K(the session key) */
int cli_recv_and_decrypt_new_session_key(int sock, int hash_idx, unsigned char pri_key_for_out[], unsigned long pri_key_for_out_len, unsigned char ses_key[]) {
    unsigned char msg_before_decrypt[1024];
    memset(msg_before_decrypt, 0, 1024);
    unsigned long msg_before_decrypt_len = sizeof(msg_before_decrypt);
    unsigned char ses_key_before_decrypt[1024];
    memset(ses_key_before_decrypt, 0, 1024);
    unsigned long ses_key_before_decrypt_len = sizeof(ses_key_before_decrypt);
    recv(sock, &msg_before_decrypt_len, sizeof(int), 0);
    recv(sock, msg_before_decrypt, msg_before_decrypt_len, 0);
    recv(sock, &ses_key_before_decrypt_len, sizeof(int), 0);
    recv(sock, ses_key_before_decrypt, ses_key_before_decrypt_len, 0);
    
    rsa_key pri_key;
    int err;
    if ((err = rsa_import(pri_key_for_out, pri_key_for_out_len, &pri_key)) != CRYPT_OK) {
        printf("Error rsa_import public: %s\n", error_to_string(err));
        return -1;
    }
    int stat1, stat2;

    /* Decrypt msg of "new_session_key" */
    unsigned char msg_after_decrypt[1024];
    memset(msg_after_decrypt, 0, 1024);
    unsigned long msg_after_decrypt_len = sizeof(msg_after_decrypt);
    if ((err = rsa_decrypt_key(msg_before_decrypt, msg_before_decrypt_len, msg_after_decrypt, &msg_after_decrypt_len, NULL, 0, hash_idx, &stat1, &pri_key)) != CRYPT_OK) {
        printf("Error rsa_decrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    if(strcmp(msg_after_decrypt, "new_session_key") == 0) {
        printf("Receive \"new_session_key\"\n");
    }
    else {
        printf("Error with receiving \"new_session_key\" and stop\n");
        exit(1);
    }

    /* Decrypt msg of K */
    unsigned char ses_key_after_decrypt[1024];
    memset(ses_key_after_decrypt, 0, 1024);
    unsigned long ses_key_after_decrypt_len = sizeof(ses_key_after_decrypt);
    if ((err = rsa_decrypt_key(ses_key_before_decrypt, ses_key_before_decrypt_len, ses_key_after_decrypt, &ses_key_after_decrypt_len, NULL, 0, hash_idx, &stat2, &pri_key)) != CRYPT_OK) {
        printf("Error rsa_decrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    strcpy(ses_key, ses_key_after_decrypt);
    return 0;
}

/* Send "ack_new_session_key" encrypted with RC6(not AES), using K */
int cli_send_ack(int sock, unsigned char ses_key[]) {
    unsigned char msg[1024];
    unsigned char msg_after_encrypt[1024];
    int err;
    memset(msg, 0, 1024);
    memset(msg_after_encrypt, 0, 1024);

    strcpy(msg, "ack_new_session_key");
    
    /* Encrypt "ack_new_session_key" */
    if (register_cipher(&rc6_desc) == -1) {
        printf("Error registering cipher.\n");
        return -1;
    }
    symmetric_CTR ctr;
    unsigned char IV[16];
    memset(IV, 0, 16);
    if ((err = ctr_start(find_cipher("rc6"), IV, ses_key, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
        printf("ctr_start error1: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_encrypt(msg, msg_after_encrypt, sizeof(msg), &ctr)) != CRYPT_OK) {
        printf("ctr_encrypt error: %s\n", error_to_string(err));
        return -1;
    }

    write(sock, msg_after_encrypt, 1024);
    return 0;
}

/* Send "encoded_msg_ok" || {data}, encrypted with RC6 using K */
int cli_send_encoded_msg(int sock, unsigned char data_string[], unsigned char ses_key[]) {
    unsigned char msg[1024] = "encoded_msg_ok";
    unsigned char msg_after_encrypt[1024];
    unsigned char data_after_encrypt[1024];
    int err;
    
    /* Encrypt "encoded_msg_ok" */
    if (register_cipher(&rc6_desc) == -1) {
        printf("Error registering cipher.\n");
        return -1;
    }
    symmetric_CTR ctr;
    unsigned char IV[16];
    memset(IV, 0, 16);
    if ((err = ctr_start(find_cipher("rc6"), IV, ses_key, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
        printf("ctr_start error2: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_encrypt(msg, msg_after_encrypt, sizeof(msg), &ctr)) != CRYPT_OK) {
        printf("ctr_encrypt error: %s\n", error_to_string(err));
        return -1;
    }
    write(sock, msg_after_encrypt, 1024);

    /* Encrypt data */
    if ((err = ctr_setiv(IV, 16, &ctr)) != CRYPT_OK) {
        printf("ctr_setiv error: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_encrypt(data_string, data_after_encrypt, 1024, &ctr)) != CRYPT_OK) {
        printf("ctr_encrypt error: %s\n", error_to_string(err));
        return -1;
    }
    write(sock, data_after_encrypt, 1024);
    return 0;
}

int main(int argc, char* argv[]) {  
    ltc_mp = ltm_desc;

    /* Client initializes the socket connection */
    int sockfd;
    struct sockaddr_in serv_addr;  
    sockfd = init(&serv_addr); 

    /* Client initializes for rsa */
    int hash_idx, prng_idx;
    prng_state prng;
    init_for_rsa(&hash_idx, &prng_idx, &prng);    

    /* Client generates its public and private keys and sends public key */
    unsigned char pub_key_for_out[1024], pri_key_for_out[1024];
    unsigned long pub_len=sizeof(pub_key_for_out)-1;
    unsigned long pri_len=sizeof(pri_key_for_out)-1;
    memset(pub_key_for_out, 0, 1024);
    cli_gen_and_send_key(sockfd, prng, prng_idx, pub_key_for_out, pri_key_for_out, pub_len, pri_len);
    
    /* Client receives server's public key */
    unsigned char pub_key_from_serv[1024];
    unsigned long pub_key_from_serv_len = sizeof(pub_key_from_serv)-1; 
    memset(pub_key_from_serv, 0, 1024);
    cli_recv_pub_key(sockfd, pub_key_from_serv, &pub_key_from_serv_len);

    /* 1A Client gets data from User Input */
    unsigned char data_string[1024]; 
    memset(data_string, 0, 1024);
    cli_get_data_from_user(data_string); 

    /* 2A: Client picks a nonceA(random number) */
    unsigned char cli_rand[28];
    rng_get_bytes(cli_rand, 28, NULL);
//    printf("Rand: %s\n", cli_rand);

    /* 3A: Client sends "req_for_session" || {nonceA} */
    cli_send_req_for_session(sockfd, prng, hash_idx, prng_idx, cli_rand, pub_key_from_serv, pub_key_from_serv_len);
    
    /* 7A: Client receives and decrypts "new_session_key" || {K} and stores session key K */
    unsigned char ses_key[16];
    cli_recv_and_decrypt_new_session_key(sockfd, hash_idx, pri_key_for_out, pri_len, ses_key);

    /* 8A: Client sends "ack_new_session_key" encrypted with RC6(not AES) using K*/
    cli_send_ack(sockfd, ses_key);

    /* 9A: Client sends "encoded_msg_ok" || {data} encrypted with RC6 using K */
    cli_send_encoded_msg(sockfd, data_string, ses_key);    
    close(sockfd);  
    return 0;  
}
