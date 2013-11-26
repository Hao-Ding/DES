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


/* structure for ServerHello MSG and ClientHello MSG */
typedef struct Hello{
    unsigned int version;
    unsigned char random[28];
    char CipherSuites[1][30];
} Hello, *pHello;

/* Init a server and wait for a connection from a client*/
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
    printf("Server has started and is waiting for a client...\n");
    return sock;
}

/* Server receive "hello" message from client */
int serv_rev_hello(int client_fd, Hello *CliHello){
    int err;
    if ((err = read(client_fd, CliHello, sizeof(Hello))) < 0) {  
        perror("reading stream error!");  
    }
    printf("2. Finished receiving hello message from client.\n...\n");
//    printf("Client SSL version: %d\nCLient random number: %s\nClient cipher suit: %s\n", CliHello->version, CliHello->random, CliHello->CipherSuites[0]);
    return err;
}

/* Server sends client "hello" message */
int serv_send_hello(int client_fd, Hello CliHello, Hello *ServHello){
    ServHello->version = 3;
    rng_get_bytes(ServHello->random, 28, NULL);
    strcpy(ServHello->CipherSuites[0], "SSL_RSA_WITH_TWOFISH_CTR_SHA1");
    /* Server chooses the highest SSL version supported by both sides */
    if (CliHello.version < ServHello->version) { 
        ServHello->version = CliHello.version;
    }
    if(send(client_fd, ServHello, sizeof(Hello),0) == -1) {
        perror("send error!");
    }
//    printf("Server random number: %s\n", ServHello->random);
    printf("3. Responsed with a hello message\n...\n");
    return 0;
}

/* Server sends its certificate and public key generated from RSA*/
int serv_send_crt_and_pub_key(int client_fd, rsa_key *pub_key, rsa_key *pri_key) {
    unsigned char ori_msg[32], crt_msg[1024], pub_key_for_out[1024], pri_key_for_out[4096];
    unsigned long ori_len = sizeof(ori_msg);
    unsigned long crt_len = sizeof(crt_msg);
    unsigned long pub_len=sizeof(pub_key_for_out)-1;
    unsigned long pri_len=sizeof(pri_key_for_out)-1;
    int hash_idx, prng_idx;
    prng_state prng;
    rsa_key key1;
    int err;

    memset(ori_msg, 0, ori_len);
    if (register_hash(&sha1_desc) == -1) {
        printf("Error registering sha1");
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
    if ((err = rsa_make_key(&prng, prng_idx, 1024/8, 65537, &key1)) !=CRYPT_OK) {
        printf("Error rsa_make_key: %s\n", error_to_string(err));
        return -1;
    }
    strcpy(ori_msg, "Server certificate");
    if ((err = rsa_sign_hash(ori_msg, ori_len, crt_msg, &crt_len, &prng, prng_idx, hash_idx, 0, &key1)) != CRYPT_OK) {
        printf("Error rsa_encrypt_key: %s\n", error_to_string(err));
        return -1;
    }
    /* Server creates public key and private key*/
    if ((err = rsa_export(pub_key_for_out, &pub_len, PK_PUBLIC, &key1)) != CRYPT_OK) {
        printf("Error rsa_export public: %s\n", error_to_string(err));
        return -1;
    }
//    printf("Public key: %s\n", pub_key_for_out);
    if ((err = rsa_import(pub_key_for_out, pub_len, pub_key))) {
        printf("Error rsa_import_public: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = rsa_export(pri_key_for_out, &pri_len, PK_PRIVATE, &key1)) != CRYPT_OK) {
        printf("Error rsa_export private: %s\n", error_to_string(err));
        return -1;
    }
//    printf("Private key: %s\n", pri_key_for_out);
    if ((err = rsa_import(pri_key_for_out, pri_len, pri_key)) != CRYPT_OK) {
        printf("Error rsa_import_private: %s\n", error_to_string(err));
        return -1;
    }
    /* Server sends crt and public key */
    if (send(client_fd, &crt_len, sizeof(int), 0) == -1) {
        perror("send error1");
    }
    if (send(client_fd, crt_msg, crt_len, 0) == -1) {
        perror("send error2");
    }
    if (send(client_fd, &pub_key_for_out, pub_len, 0) == -1) {
        perror("send error3");
    }
    printf("4. Finished sending the certificate and public key to client.\n...\n");
}

/* Server receives "key exchange message" from client and decrypts premaster secret. */
int serv_recv_key_exchange_message(int client_fd, rsa_key pri_key, unsigned char rand_nr[], unsigned long rand_nr_len, int hash_idx) {
    int stat, err;
    unsigned char tmp_msg[1024];
    unsigned long tmp_msg_len;
    memset(tmp_msg, 0, 1024);
    if ((err = read(client_fd, &tmp_msg_len, sizeof(int))) < 0) {
        perror("reading stream error!");  
    }
    if ((err = read(client_fd, tmp_msg, tmp_msg_len)) < 0) {  
        perror("reading stream error!");  
    }
//    printf("tmp_msg: %s\n",tmp_msg);
    unsigned char rand_nr_2[46];
    rand_nr_len = sizeof(rand_nr_2);
    if ((err = rsa_decrypt_key(tmp_msg, tmp_msg_len, rand_nr, &rand_nr_len, NULL, 0, hash_idx, &stat, &pri_key)) != CRYPT_OK) {
        printf("Error rsa_decrypt_key: %s\n", error_to_string(err));
        return -1;
    }
//    printf("Random nr in premaster secret is %s\n", rand_nr);
//    printf("Length of random nr is: %ld\n", rand_nr_len);
    if (stat == 1) {
        printf("7. Succeeded receiving and decrypting the premaster secret\n...\n");
    }
    return 0;
}

/* Server generates master secret. */
int serv_gen_ms_scr(unsigned char master_secret[], unsigned long ms_len, unsigned char rand1[], unsigned long rand1_len, unsigned char rand2[], unsigned long rand2_len, unsigned char rand3[], unsigned char rand3_len) {
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

/* Server generates keys for symmetric encryption and hmac */
int serv_gen_key_for_mac_sym(unsigned char ms_scr[], unsigned char key_for_mac[], unsigned char key_for_sym[]) {
    int i;
    for (i = 0; i < 16; i++) {
        key_for_mac[i] = ms_scr[i];
        key_for_sym[i] = ms_scr[16+i];
    }
    return 0;
}

/* Server receives and sends "handshake finish" message from and to client*/
int serv_recv_and_send_finish(int client_fd, unsigned char key_for_mac[], unsigned char key_for_sym[]) {
    unsigned char finish_string[] = "handshake_finished";
    unsigned char msg_from_cli[1024], hmac_from_cli[1024], msg_after_de[1024], hmac_from_serv[1024];
    unsigned long msg_from_cli_len, hmac_from_cli_len;
    symmetric_CTR ctr;
    unsigned char IV[16];
    hmac_state hmac;
    int hash_idx, err;
    
    memset(msg_from_cli, 0, 1024);
    memset(msg_after_de, 0, 1024);
    memset(hmac_from_cli, 0, 1024);
    memset(hmac_from_serv, 0, 1024);
    memset(IV, 0, 16);

    /* Server receives encrypted finish message and hmac from client */
    if ((err = read(client_fd, &msg_from_cli_len, sizeof(int))) < 0) {
        perror("reading stream error!");  
    }
    if ((err = read(client_fd, msg_from_cli, msg_from_cli_len)) < 0) {  
        perror("reading stream error!");  
    }
    if ((err = read(client_fd, &hmac_from_cli_len, sizeof(int))) < 0) {
        perror("reading stream error!");  
    }
    if ((err = read(client_fd, hmac_from_cli, hmac_from_cli_len)) < 0) {  
        perror("reading stream error!");  
    }

    /* Server checks HMAC */
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
    msg_from_cli_len = sizeof(msg_from_cli);
    if ((err = hmac_process(&hmac, msg_from_cli, msg_from_cli_len))!=CRYPT_OK){
        printf("End processing hmac: %s\n", error_to_string(err));
        return -1;
    }
    unsigned long hmac_from_serv_len = sizeof(hmac_from_serv);
    if ((err = hmac_done(&hmac, hmac_from_serv, &hmac_from_serv_len))!=CRYPT_OK){
        printf("End finishing hmac: %s\n", error_to_string(err));
        return -1;
    }
    if (strcmp(hmac_from_cli, hmac_from_serv) == 0) {
        printf("9. \"handshake finish\" hmac from client is correct!\n...\n");
    }
    else {
        printf("hmac wrong!\n");
    }
    /* Server decrypts the msg from client and checks it*/
    if (register_cipher(&twofish_desc) == -1) {
        printf("Error registering cipher.\n");
        return -1;
    }
    if ((err = ctr_start(find_cipher("twofish"), IV, key_for_sym, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
        printf("ctr_start error: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_decrypt(msg_from_cli, msg_after_de, sizeof(msg_after_de), &ctr)) != CRYPT_OK) {
        printf("ctr_decrypt error: %s\n", error_to_string(err));
        return -1;
    }
//    printf("Msg after decrypt=%s\n", msg_after_de);
    if (strcmp(msg_after_de, finish_string) != 0) {
        printf("Wrong decrypted finish msg.\n");
        return -1;
    }
    else {
        printf("10. \"handshake finish\" msg from client is correct!!!\n...\n");
    }
    /* Sym encrypt */
    if ((err = ctr_setiv(IV, 16, &ctr)) != CRYPT_OK) {
        printf("ctr_setiv error: %s\n", error_to_string(err));
        return -1;
    }
    unsigned char tmp_string[1024];
    unsigned long tmp_len = sizeof(tmp_string);
    if ((err = ctr_encrypt(finish_string, tmp_string, sizeof(finish_string), &ctr)) != CRYPT_OK) {
        printf("ctr_encrypt error: %s\n", error_to_string(err));
        return -1;
    }
    /* Server sends hmac and encrypted msg */
    if (send(client_fd, &hmac_from_serv_len, sizeof(int), 0) == -1) {
        perror("send error1");
    }
    if (send(client_fd, hmac_from_serv, hmac_from_serv_len, 0) == -1) {
        perror("send error2");
    }
    if (send(client_fd, &tmp_len, sizeof(int), 0) == -1) {
        perror("send error1");
    }
    if (send(client_fd, tmp_string, tmp_len, 0) == -1) {
        perror("send error2");
    }
    printf("11. Sent the client \"handshake finish\" msg and its hmac\n...\n");
    printf("Handshake on server side finishes and waits for data from client...\n...\n\n");
    return 0;
}

/* Server receives data from client and display the data*/
int serv_recv_data_and_display(int client_fd, unsigned char key_for_mac[], unsigned char key_for_sym[]) {
    unsigned char msg_from_cli[1024], hmac_from_cli[1024], msg_after_de[1024], hmac_from_serv[1024];
    unsigned long msg_from_cli_len, hmac_from_cli_len;
    symmetric_CTR ctr;
    unsigned char IV[16];
    hmac_state hmac;
    int hash_idx, err;
    
    memset(msg_from_cli, 0, 1024);
    memset(msg_after_de, 0, 1024);
    memset(IV, 0, 16);

    /* Server receives encrypted finish message and hmac from client */
    if ((err = read(client_fd, &msg_from_cli_len, sizeof(int))) < 0) {
        perror("reading stream error!");  
    }
    if ((err = read(client_fd, msg_from_cli, msg_from_cli_len)) < 0) {  
        perror("reading stream error!");  
    }
    if ((err = read(client_fd, &hmac_from_cli_len, sizeof(int))) < 0) {
        perror("reading stream error!");  
    }
    if ((err = read(client_fd, hmac_from_cli, hmac_from_cli_len)) < 0) {  
        perror("reading stream error!");  
    }

    /* Firstly, check the correctness of HMAC */
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
    msg_from_cli_len = sizeof(msg_from_cli);
    if ((err = hmac_process(&hmac, msg_from_cli, msg_from_cli_len))!=CRYPT_OK){
        printf("End processing hmac: %s\n", error_to_string(err));
        return -1;
    }
    unsigned long hmac_from_serv_len = sizeof(hmac_from_serv);
    if ((err = hmac_done(&hmac, hmac_from_serv, &hmac_from_serv_len))!=CRYPT_OK){
        printf("End finishing hmac: %s\n", error_to_string(err));
        return -1;
    }
    if (strcmp(hmac_from_cli, hmac_from_serv) == 0) {
//        printf("hmac correct!\n");
    }
    else {
        printf("hmac wrong!\n");
        return -1;
    }
    /* Server decrypts the msg from client and checks it*/
    if (register_cipher(&twofish_desc) == -1) {
        printf("Error registering cipher.\n");
        return -1;
    }
    if ((err = ctr_start(find_cipher("twofish"), IV, key_for_sym, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK) {
        printf("ctr_start error: %s\n", error_to_string(err));
        return -1;
    }
    if ((err = ctr_decrypt(msg_from_cli, msg_after_de, sizeof(msg_after_de), &ctr)) != CRYPT_OK) {
        printf("ctr_decrypt error: %s\n", error_to_string(err));
        return -1;
    }
    printf("Data from client: \n%s\n", msg_after_de);
    printf("One procedure of SSL finishes and please run client again for another communication.\n");
    return 0;
}

int main() {  
    ltc_mp = ltm_desc;
    int sockfd, client_fd;  
    struct sockaddr_in my_addr;  
    struct sockaddr_in remote_addr;  
    Hello CHello, SHello;
	
    memset(&CHello, 0, sizeof(Hello));
    memset(&SHello, 0, sizeof(Hello));
    
    /* Start a server and wait for a client. */
    sockfd = init(&my_addr);
    
    while (1) {  
        socklen_t sin_size = sizeof(struct sockaddr_in);  
        /* Receive a client. */
        if ((client_fd = accept(sockfd,(struct sockaddr*) &remote_addr,&sin_size)) == -1){  
            perror("accept error!");  
            continue;  
        }  
        printf("Received a connection from %s\n", (char*)inet_ntoa(remote_addr.sin_addr));  

        /* Generate a process for the client. */
        if (!fork()){ 
            int rval;
            unsigned char original_msg[32], crt_msg[1024], public_key[1024], private_key[4096];
            prng_state prng;
            int err;
            int hash_idx, prng_idx;
			
            memset(public_key, 0, sizeof(public_key));
            memset(private_key, 0, sizeof(private_key));
            memset(original_msg, 0, sizeof(original_msg));
            memset(crt_msg, 0, 1024);
            unsigned long crt_len = 1024;
            unsigned long ori_len = sizeof(original_msg);

            /* Server receives hello message from the client */
            if ((err = serv_rev_hello(client_fd, &CHello)) < 0) {
                continue;
            }

            /* Server responses the hello from client */
            serv_send_hello(client_fd, CHello, &SHello);

            /* Server creates and sends the certificate and public key*/  
            rsa_key pub_key, pri_key;
            serv_send_crt_and_pub_key(client_fd, &pub_key, &pri_key);

            /* Server receives the key exchange message and decrypts it*/
            unsigned char rn_in_pre[46];
            unsigned long rn_in_pre_len = sizeof(rn_in_pre);
            memset(rn_in_pre, 0, 46);
            serv_recv_key_exchange_message(client_fd, pri_key, rn_in_pre, rn_in_pre_len, hash_idx);

            /* Server generates the master secret. */
            unsigned char ms_scr[48];
            serv_gen_ms_scr(ms_scr, 48, CHello.random, 28, SHello.random, 28, rn_in_pre, 46);
            unsigned char key_for_mac[16], key_for_sym[16];

            /* Server generates keys for symmetric encryption and hmac. */
            serv_gen_key_for_mac_sym(ms_scr, key_for_mac, key_for_sym);

            /* Server receives and then sends "handshake finish" message*/
            serv_recv_and_send_finish(client_fd, key_for_mac, key_for_sym);

            /* Server receives data from client and displays */
            serv_recv_data_and_display(client_fd, key_for_mac, key_for_sym);

            /* Terminate the socket for the client */
            close(client_fd);  
            exit(0);  
        }  
        close(client_fd);  
    }  
    return 0;  
}
