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

/* structure for ServerHello MSG and ClientHello MSG */
typedef struct Hello{
    unsigned int version;
    unsigned char random[28];
    char CipherSuites[1][30];
} Hello, *pHello;  

/* Init a client and connect the server */
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

/* Client sends "hello" message to the server */
int client_send_hello(int sock, Hello *CliHello){
    CliHello->version = 3;
    rng_get_bytes(CliHello->random, 28, NULL);
    strcpy(CliHello->CipherSuites[0], "SSL_RSA_WITH_TWOFISH_CTR_SHA1");
    if (write(sock, CliHello, sizeof(Hello)) == sizeof(Hello)) {
        printf("1. Finished sending hello to server.\n...\n");
    }
    
    return 0;
}

/* Client receives "hello" message from the server */
int client_rev_hello(int sock, Hello *ServHello){
    int err;
    if ((err = recv(sock, ServHello, sizeof(Hello), 0)) == -1) {              
        perror("recv error!");
        exit(1);
    }
    return 0;
}

/* Client receives certificate from the server */
unsigned long client_recv_crt(int sockfd, unsigned char crt_msg[], unsigned long crt_len) {
    int recvbytes;
    memset(crt_msg, 0, crt_len);
    if ((recvbytes = recv(sockfd, (void *)&crt_len, sizeof(int), 0)) == -1) {
       perror("recv error");
       exit(1);
    }
    if ((recvbytes = recv(sockfd, (void *)crt_msg, crt_len, 0)) == -1) {
        perror("recv error!");
        exit(1);
    }
//    printf("Crt_msg: %s\n", crt_msg);	
    return crt_len;
}


/* Client receives public key */
int client_recv_pub_key(int sockfd, unsigned char public_key[], unsigned long public_len) {
    int recvbytes;
    memset(public_key, 0, public_len);

    if ((recvbytes = recv(sockfd, (void *)public_key, public_len, 0)) == -1) {
        perror("recv error!");
        exit(1);
    }
//    printf("Public key: %s\n", public_key);
    return 0;
}

/* Client verifyes the certificate */
int client_verify_crt(unsigned char public_key[], unsigned long public_len, unsigned char crt_msg[], unsigned long crt_len, int hash_idx, rsa_key *key1) {
    unsigned char ori_msg[32];
    unsigned long ori_len = sizeof(ori_msg);
    int err;

    memset(ori_msg, 0, ori_len);
    strcpy(ori_msg, "Server certificate");

    if ((err = rsa_import(public_key, public_len, key1)) != CRYPT_OK) {
        printf("Error rsa_import: %s\n", error_to_string(err));
        return -1;
    }
    int stat=0;
    if ((err = rsa_verify_hash(crt_msg, crt_len, ori_msg, ori_len, hash_idx, 0, &stat, key1)) != CRYPT_OK) {
        printf("Error rsa_verify_hash: %s\n", error_to_string(err));
        return -1;
    }
/*
    if (stat == 0) {
        printf("Wrong certificate\n");
    }
    else {
        printf("Correct certificate\n");
    }
*/
    return stat;
}

/* Client sends "key exchange message" with premaster secret */
int cli_send_key_exchange_message(int sock, unsigned char premaster_secret[], unsigned long len, prng_state prng, int prng_idx, int hash_idx, rsa_key key) {
    int err;
    unsigned char secret_msg[1024];
    unsigned long secret_msg_len = sizeof(secret_msg);
    memset(secret_msg, 0, sizeof(secret_msg));
    rng_get_bytes(premaster_secret, len, NULL);
    if ((err = rsa_encrypt_key(premaster_secret, len, secret_msg, &secret_msg_len, NULL, 0, &prng, prng_idx, hash_idx, &key)) != CRYPT_OK) {
        printf("Error rsa_encrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    write(sock, &secret_msg_len, sizeof(int));
    write(sock, secret_msg, secret_msg_len);
//    printf("secret_msg: %s\nsecret_msg_len=%ld",secret_msg, secret_msg_len);
    printf("6. Sent server a key exchange message, including the encrypted premaster secret.\n...\n");
    return 0;
}

/* Client generates master secret */
int cli_gen_ms_scr(unsigned char master_secret[], unsigned long ms_len, unsigned char rand1[], unsigned long rand1_len, unsigned char rand2[], unsigned long rand2_len, unsigned char rand3[], unsigned char rand3_len) {
    unsigned long tmp_len = rand1_len + rand2_len + rand3_len;
    unsigned char *tmp = (unsigned char *)malloc(tmp_len * sizeof(unsigned long));
    int i, err;
    prng_state prng;

    for (i = 0; i < rand1_len; i++) {
        tmp[i] = rand1[i];
    }
    for (i = 0; i < rand2_len; i++) {
        tmp[rand1_len + i] = rand2[i];
    }
    for (i = 0; i < rand3_len; i++) {
        tmp[rand1_len + rand2_len + i] = rand3[i];
    }
    if ((err = yarrow_start(&prng)) != CRYPT_OK) {
        printf("Start error: %s\n", error_to_string(err));
    }
    if ((err = yarrow_add_entropy(tmp, tmp_len, &prng)) != CRYPT_OK) {
        printf("Add_entropy error: %s\n", error_to_string(err));
    }
    if ((err = yarrow_ready(&prng)) != CRYPT_OK) {
        printf("Ready error: %s\n", error_to_string(err));
    }
    yarrow_read(master_secret, ms_len, &prng);
//    printf("master_secret=%s\n", master_secret);
    return 0;
}

/* Client generates keys for symmetric encryption and hmac */
int cli_gen_key_for_mac_sym(unsigned char ms_scr[], unsigned char key_for_mac[], unsigned char key_for_sym[]) {
    int i;
    for (i = 0; i < 16; i++) {
        key_for_mac[i] = ms_scr[i];
        key_for_sym[i] = ms_scr[16+i];
    }
    return 0;
}

/* Client sends and then receives "handshake finish" message to and from the server */
int cli_send_and_recv_finish(int sock, unsigned char key_for_mac[], unsigned char key_for_sym[]) {
    unsigned char finish_string[1024] = "handshake_finished";
    unsigned char tmp_string[1024], hmac_from_cli[1024], hmac_from_serv[1024], msg_from_serv[1024], msg_after_de[1024];
    unsigned long tmp_len, hmac_from_cli_len, hmac_from_serv_len, msg_from_serv_len;
    symmetric_key skey;
    hmac_state hmac;
    int hash_idx, err;
    
    memset(tmp_string, 0, 1024);
    memset(hmac_from_cli, 0, 1024);
    memset(hmac_from_serv, 0, 1024);
    /* Sym encrypt */
    if (register_cipher(&twofish_desc) == -1) {
        printf("Error registering cipher.\n");
        return -1;
    }
    symmetric_CTR ctr;
    unsigned char IV[16];
//    rng_get_bytes(IV, 16, NULL);
    memset(IV, 0, 16);
    if ((err = ctr_start(find_cipher("twofish"), IV, key_for_sym, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
        printf("ctr_start error: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_encrypt(finish_string, tmp_string, sizeof(finish_string), &ctr)) != CRYPT_OK) {
        printf("ctr_encrypt error: %s\n", error_to_string(err));
        return -1;
    }
    /* MAC */
    if (register_hash(&sha1_desc) == -1) {
        printf("Error registering sha1");
        return -1;
    }
    if ((hash_idx = find_hash("sha1")) == -1) {
        printf("hash_idx = %d\n", hash_idx);
        printf("rsa_test requires LTC_SHA1\n");
        return -1;
    }
    if ((err = hmac_init(&hmac, hash_idx, key_for_sym, 16))!=CRYPT_OK){
        printf("Init error: %s\n", error_to_string(err));
        return -1;
    }
    tmp_len = sizeof(tmp_string);
    if ((err = hmac_process(&hmac, tmp_string, tmp_len))!=CRYPT_OK){
        printf("End processing hmac: %s\n", error_to_string(err));
        return -1;
    }
    hmac_from_cli_len = sizeof(hmac_from_cli);
    if ((err = hmac_done(&hmac, hmac_from_cli, &hmac_from_cli_len))!=CRYPT_OK){
        printf("End finishing hmac: %s\n", error_to_string(err));
        return -1;
    }
    if (write(sock, &tmp_len, sizeof(int)) < 0) {
        //printf("1. Finished sending hello to server.\n...\n");
    }
    if (write(sock, tmp_string, tmp_len) < 0) {
        //printf("1. Finished sending hello to server.\n...\n");
    }
    if (write(sock, &hmac_from_cli_len, sizeof(int)) < 0) {
        //printf("1. Finished sending hello to server.\n...\n");
    }
    if (write(sock, hmac_from_cli, hmac_from_cli_len) < 0) {
        //printf("1. Finished sending hello to server.\n...\n");
    }
    printf("8. Sent \"handshake finish\" msg and its hmac\n...\n");
    /* Client receives hmac and encrypted msg from server */
    if (recv(sock, &hmac_from_serv_len, sizeof(int), 0) == -1) {
        perror("recv error!");
        exit(1);
    }
    if (recv(sock, hmac_from_serv, hmac_from_serv_len, 0) == -1) {
        perror("recv error!");
        exit(1);
    }
    if (recv(sock, &msg_from_serv_len, sizeof(int), 0) == -1) {
        perror("recv error!");
        exit(1);
    }
    if (recv(sock, msg_from_serv, msg_from_serv_len, 0) == -1) {
        perror("recv error!");
        exit(1);
    }
    
    /* Client checks the hmac and encrypted msg */
    if (strcmp(hmac_from_cli, hmac_from_serv) == 0) {
//        printf("hmac correct!\n");
    }
    else {
        printf("hmac wrong!\n");
    }
    if ((err = ctr_setiv(IV, 16, &ctr)) != CRYPT_OK) {
        printf("ctr_setiv error: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_decrypt(msg_from_serv, msg_after_de, sizeof(msg_after_de), &ctr)) != CRYPT_OK) {
        printf("ctr_decrypt error: %s\n", error_to_string(err));
        return -1;
    }
//    printf("Msg after decrypt=%s\n", msg_after_de);
    if (strcmp(msg_after_de, finish_string) != 0) {
        printf("Wrong decrypted results.\n");
        return -1;
    }
    else {
        printf("12. \"handshake finish\"  and its hmac from the server are correct!\n\nNow handshake finishes, and you could type something...\n\n");
    }
    return 0;
}

/* Client gets data from user and then send them */
int cli_get_data_and_send(int sock, unsigned char key_for_mac[], unsigned char key_for_sym[]) {
    unsigned char data_string[1024];
    unsigned char tmp_string[1024], hmac_from_cli[1024], hmac_from_serv[1024], msg_from_serv[1024], msg_after_de[1024];
    unsigned long tmp_len, hmac_from_cli_len, hmac_from_serv_len, msg_from_serv_len;
    symmetric_key skey;
    hmac_state hmac;
    int hash_idx, err;
    
    memset(data_string, 0, 1024);
    memset(tmp_string, 0, 1024);

    /* Client gets data from user */
    printf("\nPlease input data: ");
    int i = 0;
    do {
        scanf("%c", &data_string[i]);
        i++;
    } while(data_string[i-1] != '\n');

    /* Sym encrypt */
    if (register_cipher(&twofish_desc) == -1) {
        printf("Error registering cipher.\n");
        return -1;
    }
    symmetric_CTR ctr;
    unsigned char IV[16];
//    rng_get_bytes(IV, 16, NULL);
    memset(IV, 0, 16);
    if ((err = ctr_start(find_cipher("twofish"), IV, key_for_sym, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
        printf("ctr_start error: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_encrypt(data_string, tmp_string, sizeof(data_string), &ctr)) != CRYPT_OK) {
        printf("ctr_encrypt error: %s\n", error_to_string(err));
        return -1;
    }
    /* MAC */
    if (register_hash(&sha1_desc) == -1) {
        printf("Error registering sha1");
        return -1;
    }
    if ((hash_idx = find_hash("sha1")) == -1) {
        printf("hash_idx = %d\n", hash_idx);
        printf("rsa_test requires LTC_SHA1\n");
        return -1;
    }
    if ((err = hmac_init(&hmac, hash_idx, key_for_sym, 16))!=CRYPT_OK){
        printf("Init error: %s\n", error_to_string(err));
        return -1;
    }
    tmp_len = sizeof(tmp_string);
    if ((err = hmac_process(&hmac, tmp_string, tmp_len))!=CRYPT_OK){
        printf("End processing hmac: %s\n", error_to_string(err));
        return -1;
    }
    hmac_from_cli_len = sizeof(hmac_from_cli);
    if ((err = hmac_done(&hmac, hmac_from_cli, &hmac_from_cli_len))!=CRYPT_OK){
        printf("End finishing hmac: %s\n", error_to_string(err));
        return -1;
    }
    write(sock, &tmp_len, sizeof(int));
    write(sock, tmp_string, tmp_len);
    write(sock, &hmac_from_cli_len, sizeof(int));
    write(sock, hmac_from_cli, hmac_from_cli_len); 
    return 0;
}

int main(int argc, char* argv[]) {  
    ltc_mp = ltm_desc;
    int sockfd, recvbytes;  

    struct sockaddr_in serv_addr;  
    Hello CHello;
    Hello SHello;	
    unsigned char crt_msg[1024], public_key[1024];
    unsigned long public_len = sizeof(public_key)-1;
    unsigned long crt_len = sizeof(crt_msg);
    int err, stat_verify;

    memset(&CHello, 0, sizeof(Hello));
    memset(&SHello, 0, sizeof(Hello));
    memset(crt_msg, 0, 1024);
    memset(public_key, 0, 1024);

    /* Init a client */
    sockfd = init(&serv_addr);  
    
    /* Client sends "hello" message */    
    client_send_hello(sockfd, &CHello);

    /* Client receives "hello" message */
    client_rev_hello(sockfd, &SHello);

    /* Client receives certificate from server */
    crt_len = client_recv_crt(sockfd, crt_msg, crt_len);

    /* Client receives public key from server */
    client_recv_pub_key(sockfd, public_key, public_len);
    
    /* Client verifys the certificate from server */
    int hash_idx, prng_idx;
    rsa_key key1;
    prng_state prng;
    if (register_hash(&sha1_desc) == -1) {
        printf("Error registering sha1\n");
        return -1;
    }
    if (register_prng(&yarrow_desc) == -1) {
        printf("Error registering Yarrow\n");
        return -1;
    }
    if ((hash_idx = find_hash("sha1")) == -1 || (prng_idx = find_prng("yarrow")) == -1) {
        printf("hash_idx = %d\nprng_idx = %d\n", hash_idx, prng_idx);
        printf("rsa_test requires LTC_SHA1 and yarrow\n");
        return -1;
    }
    if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
        printf("Error rng_make_prng: %s\n", error_to_string(err));
        return -1;
    }
    if ((stat_verify = client_verify_crt(public_key, public_len, crt_msg, crt_len, hash_idx, &key1) )== 0) {
        printf("Client fails to verify the certificate from server\n");
        exit(1);
    }
    else {
        printf("5. Succeeded verifying certificate from server.\n...\n");
    }

    /* Client sends a key exchange message, generates a 48-byte premaster secret and encrypts it with public key. The 48-byte premester secret is composed of 2 bytes identifying the client version and 46 random bytes*/
    unsigned char premaster_secret[46];
    unsigned long len = sizeof(premaster_secret);
    memset(premaster_secret, 0, 46);
    cli_send_key_exchange_message(sockfd, premaster_secret, len, prng, prng_idx, hash_idx, key1);

    /* Client generates the master secret. */
    unsigned char ms_scr[48];
    cli_gen_ms_scr(ms_scr, 48, CHello.random, 28, SHello.random, 28, premaster_secret, 46);

    /* Client generates keys for symmetric encryption and hmac */
    unsigned char key_for_mac[16], key_for_sym[16];
    cli_gen_key_for_mac_sym(ms_scr, key_for_mac, key_for_sym);
    
    /* Client sends and then receives "handshake finish" message */
    cli_send_and_recv_finish(sockfd, key_for_mac, key_for_sym);    

    /* Client gets data from user and then sends them */ 
    cli_get_data_and_send(sockfd, key_for_mac, key_for_sym); 

    /* Terminate the client */
    close(sockfd);  
    return 0;  
}
