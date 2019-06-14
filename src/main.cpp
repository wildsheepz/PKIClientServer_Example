//============================================================================
// Name        : PKITestFramework.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include <iostream>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <cmath>

#include "app_enums.h"
#include "ssl_ocsp.h"

static char ipaddr[16] = "127.0.0.1";
static char port[6] = "1234";

#define MAX_PKT_SIZE    1441
static size_t Pktlen = MAX_PKT_SIZE;
static uint8_t sendbuf[MAX_PKT_SIZE];
static uint8_t recvbuf[MAX_PKT_SIZE];

struct header {
	std::string filename;
	size_t payloadSz;
};

using namespace klass_ssl_ocsp;

inline const char * separator() {
#ifdef _WIN32
	return "\\";
#else
	return "/";
#endif
}

void print_debug_msg(log_t level, const char message[]) {
	std::cout << "[" << level << "]: " << message << std::endl;
}

uint32_t recv_header(BIO * bio, header * header) {
	uint32_t dataLength;
	uint32_t filename_len;
	int ret;
	ret = BIO_read(bio, &dataLength, sizeof(size_t));
	if (ret <= 0) {
		std::cerr << "err " << std::endl;
	}
	filename_len = ntohl(dataLength); // Ensure host system byte order
	std::cout << "filename_len " << filename_len << std::endl;

	ret = BIO_read(bio, &dataLength, sizeof(size_t));
	if (ret <= 0) {
		std::cerr << "err " << std::endl;
	}
	header->payloadSz = ntohl(dataLength); // Ensure host system byte order
	std::cout << "header->payloadSz: " << header->payloadSz << std::endl;

	std::vector<char> rcvBuf;    // Allocate a receive buffer
	rcvBuf.resize(filename_len, 0x00); // with the necessary size

	ret = BIO_read(bio, &(rcvBuf[0]), filename_len); // Receive the string data
	if (ret <= 0) {
		std::cerr << "err " << std::endl;
	}
	header->filename.assign(&(rcvBuf[0]), rcvBuf.size());
	std::cout << "header->filename " << header->filename << std::endl;

	BIO_flush(bio);
	return FLAG_READY;
}

uint32_t send_header(BIO * bio, const char* fn, size_t payloadSz) {
	uint32_t ret = 0;
	std::string filename(fn);

	// Remove directory if present.
	// Do this before extension removal incase directory has a period character.
	const size_t last_slash_idx = filename.find_last_of("\\/");
	if (std::string::npos != last_slash_idx) {
		filename.erase(0, last_slash_idx + 1);
	}

	size_t filename_len = htonl(filename.size()); // Ensure network byte order when sending the data length
	ret = BIO_write(bio, &filename_len, sizeof(size_t));
	if (ret <= 0) {
		return FLAG_ERROR;
	}
	size_t payloadSz_net = htonl(payloadSz);
	ret = BIO_write(bio, &payloadSz_net, sizeof(size_t));
	if (ret <= 0) {
		return FLAG_ERROR;
	}
	ret = BIO_write(bio, filename.c_str(), filename.size());
	if (ret <= 0) {
		return FLAG_ERROR;
	}
	std::cout << "filename_len " << filename.size() << std::endl;
	std::cout << "fn " << fn << std::endl;
	std::cout << "payloadSz " << payloadSz << std::endl;
	return FLAG_READY;
}

void sender(SSL_CTX * ctx, const char * sendfilename) {
	BIO *sbio;
	SSL *ssl;

	sbio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(sbio, &ssl);
	if (ssl == NULL) {
		fprintf(stderr, "Can't locate SSL pointer\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	verifyOwnCert(ctx, ssl);
	/* Don't want any retries */
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_callback);
	BIO_set_conn_hostname(sbio, ipaddr);
	BIO_set_conn_port(sbio, port);
	if (BIO_do_connect(sbio) <= 0) {
		fprintf(stderr, "Error connecting to server\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (BIO_do_handshake(sbio) <= 0) {
		fprintf(stderr, "Error establishing SSL connection\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	ShowCerts(ssl);

	FILE *fs = fopen(sendfilename, "rb");
	if (fs == NULL) {
		print_debug_msg(LOG_TRACE, "ERROR: File not found.\n");
		return;
	}
	bzero(sendbuf, Pktlen);

	ssize_t fs_block_sz = 0;
	uint32_t ii;

	//Get file size
	fseek(fs, 0L, SEEK_END);
	size_t fileSz = ftell(fs);
	fseek(fs, 0L, SEEK_SET);
	std::cout << "sending: " << sendfilename << " of size: " << fileSz
			<< std::endl;
	send_header(sbio, sendfilename, fileSz);

	ii = 0;
	size_t tot_send_sz = 0;
	bzero(sendbuf, Pktlen);
	uint32_t result = FLAG_READY;
	int count;
	while ((fs_block_sz = fread(sendbuf, sizeof(uint8_t), Pktlen, fs)) > 0) {
		BIO_write(sbio, sendbuf, fs_block_sz);
		tot_send_sz += fs_block_sz;
		ii++;
		bzero(sendbuf, Pktlen);
	}
	count = BIO_read(sbio, &result, sizeof(uint32_t));
	if (count > 0) {
		if (result == FLAG_ERROR) {
			std::cerr << "ERROR Occurred when sending." << std::endl;
		}
	} else {
		std::cerr << "ERROR Occurred when sending." << std::endl;
	}
	fclose(fs);
	BIO_free_all(sbio);
}

void receiver(SSL_CTX * ctx, const char * dest_folder) {
	BIO * sbio, *bbio, *acpt;
	SSL * ssl;
	sbio = BIO_new_ssl(ctx, 0);
	BIO_get_ssl(sbio, &ssl);
	if (ssl == NULL) {
		fprintf(stderr, "Can't locate SSL pointer\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	verifyOwnCert(ctx, ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_callback);
	bbio = BIO_new(BIO_f_buffer());
	sbio = BIO_push(bbio, sbio);
	acpt = BIO_new_accept(port);

	/*
	 * By doing this when a new connection is established
	 * we automatically have sbio inserted into it. The
	 * BIO chain is now 'swallowed' by the accept BIO and
	 * will be freed when the accept BIO is freed.
	 */
	BIO_set_accept_bios(acpt, sbio);

	std::cout << "Waiting for connection ..." << std::endl;
	/* Setup accept BIO */
	if (BIO_do_accept(acpt) <= 0) {
		fprintf(stderr, "Error setting up accept BIO\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (BIO_do_accept(acpt) <= 0) {
		fprintf(stderr, "Error in connection\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* We only want one connection so remove and free accept BIO */
	sbio = BIO_pop(acpt);
	BIO_free_all(acpt);

	if (BIO_do_handshake(sbio) <= 0) {
		fprintf(stderr, "Error in SSL handshake\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	BIO_get_ssl(sbio, &ssl);
	ShowCerts(ssl);

	header h;
	recv_header(sbio, &h);
	// Read from client
	bzero(recvbuf, Pktlen);

	FILE *fr;
	std::string output_file_path =
			std::string(dest_folder).append(separator()).append(h.filename);
	fr = fopen(output_file_path.c_str(), "wb");
	if (fr == NULL) {
		std::cerr << "pid: " << getpid() << " - Cannot open file: "
				<< h.filename.c_str() << std::endl;
		return;
	}
	fclose(fr);
	size_t TotalReceived = 0, received;
	size_t pending;
	while (TotalReceived < h.payloadSz) {
		pending = std::min(BIO_ctrl_pending(sbio), Pktlen);
		received = BIO_read(sbio, recvbuf, pending);
		if (received > 0) {
			TotalReceived += received;
//			printf("PID %i Buffsize - %i - %.*s \n", getpid(), received,
//					received, recvbuf);
			fr = fopen(output_file_path.c_str(), "ab");
			size_t write_sz = fwrite(recvbuf, sizeof(uint8_t), received, fr);
			if (write_sz < received) {
				print_debug_msg(LOG_TRACE, "File write failed.\n");
			}
			fclose(fr);
		} else {
			// received zero bytes..?
		}
		bzero(recvbuf, Pktlen);
	}
	uint32_t status = FLAG_READY;
	BIO_write(sbio, &status, sizeof(uint32_t));
	BIO_flush(sbio);
	BIO_shutdown_wr(sbio);
	BIO_free_all(sbio);
}

int main(int argc, char** argv) {
#ifdef CLIENT
	if (argc != 4) {
		std::cerr << "Usage: " << argv[0]
				<< " <destination-ipaddr> <destination-port> <path/to/input/file>"
				<< std::endl;
		return -1;
	}
	if (strlen(argv[1]) <= 16)
		strcpy(ipaddr, argv[1]);
	else {
		std::cerr << "Wrong ip address" << std::endl;
		return -2;
	}
	char * portIn = argv[2];
	const char * file_to_be_sent_path = argv[3];
#endif
#ifdef SERVER
	if (argc != 3) {
		std::cerr << "Usage: " << argv[0]
		<< " <destination-port> <path/to/dest/folder>"
		<< std::endl;
		return -1;
	}
	char * portIn = argv[1];
	char * dest_folder = argv[2];
#endif

	if (strlen(portIn) <= 6) {
		strcpy(port, portIn);
	} else {
		std::cerr << "Wrong port number" << std::endl;
		return -3;
	}

	SSL_CTX * ctx;
#ifdef SERVER
	const char * cert_file_path = "user.crt";
	const char * pvtkey_file_path = "user-pvt.key";
	const char * ca_cert_path = "ca.crt";
	ctx = initSSLServerCtx(cert_file_path, pvtkey_file_path);
	initCAStore(ctx, ca_cert_path);
	receiver(ctx, dest_folder);
#endif
#ifdef CLIENT
	const char * cert_file_path = "user2.crt";
	const char * pvtkey_file_path = "user2-pvt.key";
	const char * ca_cert_path = "ca.crt";
	ctx = initSSLClientCtx(cert_file_path, pvtkey_file_path);
	initCAStore(ctx, ca_cert_path);
	sender(ctx, file_to_be_sent_path);
#endif
	BIO_free(bio_err);
	return 0;
}
