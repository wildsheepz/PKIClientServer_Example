/*
 * ssl_stuff.h
 *
 *  Created on: Jun 9, 2019
 *      Author: kuanyong
 */

#ifndef SSL_STUFF_H_
#define SSL_STUFF_H_

#include <vector>
#include <string>
#include <iostream>

#include <openssl/ocsp.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace klass_ssl_ocsp {

#define openssl_fdset(a,b) FD_SET(a, b)

static BIO * bio_err;
static X509_STORE * store;

std::vector<std::string> ocsp_urls(X509 *x509);

std::string cert_value2str(X509_NAME *subject);

OCSP_RESPONSE *query_responder(BIO *cbio, const char *host,
		const char *path, const STACK_OF(CONF_VALUE) *headers,
		OCSP_REQUEST *req, int req_timeout);

OCSP_RESPONSE *process_responder(BIO* bio_err, OCSP_REQUEST *req, const char *host,
		const char *path, const char *port, int use_ssl,
		STACK_OF(CONF_VALUE) *headers, int req_timeout);
/*
 * Helper function to get an OCSP_RESPONSE from a responder. This is a
 * simplified version. It examines certificates each time and makes one OCSP
 * responder query for each request. A full version would store details such as
 * the OCSP certificate IDs and minimise the number of OCSP responses by caching
 * them until they were considered "expired".
 */
int get_ocsp_resp_from_responder(SSL *s, OCSP_RESPONSE **resp);
bool ocsp_verify(SSL* ssl, X509* cert, std::string & url);

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);

void init_openssl();

void ShowCerts(SSL* ssl);

void cleanup_openssl();
SSL_CTX * create_ssl_server_context();

SSL_CTX * create_ssl_client_context();

// Check ssl error
void sslError(SSL *ssl, int received);

void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile);

SSL_CTX * initSSLServerCtx(const char * cert_path, const char * pvtKey_path);
SSL_CTX * initSSLClientCtx(const char * cert_path, const char * pvtKey_path);

void initCAStore(SSL_CTX*ctx, const char* ca_cert_file_path);
void verifyOwnCert(SSL_CTX*ctx, SSL * ssl);
}
#endif /* SSL_STUFF_H_ */
