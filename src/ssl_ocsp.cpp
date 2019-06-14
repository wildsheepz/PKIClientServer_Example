/*
 * ssl_stuff.cpp
 *
 *  Created on: Jun 14, 2019
 *      Author: kuanyong
 */
#include "ssl_ocsp.h"
#include <string.h>

namespace klass_ssl_ocsp {

std::vector<std::string> ocsp_urls(X509 *x509) {
	std::vector<std::string> list;
	STACK_OF(OPENSSL_STRING) * ocsp_list = X509_get1_ocsp(x509);
	for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list); j++) {
		list.push_back(std::string(sk_OPENSSL_STRING_value(ocsp_list, j)));
	}
	X509_email_free(ocsp_list);
	return list;
}

OCSP_RESPONSE * process_responder(OCSP_REQUEST *req, const char *host,
		const char *path, const char *port, int use_ssl,
		STACK_OF(CONF_VALUE) *headers, int req_timeout) {
	BIO *cbio = NULL;
	SSL_CTX *ctx = NULL;
	OCSP_RESPONSE *resp = NULL;

	cbio = BIO_new_connect(host);
	if (cbio == NULL) {
		BIO_printf(bio_err, "Error creating connect BIO\n");
		goto end;
	}
	if (port != NULL)
		BIO_set_conn_port(cbio, port);
	if (use_ssl == 1) {
		BIO *sbio;
		ctx = SSL_CTX_new(TLS_client_method());
		if (ctx == NULL) {
			BIO_printf(bio_err, "Error creating SSL context.\n");
			goto end;
		}
		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
		sbio = BIO_new_ssl(ctx, 1);
		cbio = BIO_push(sbio, cbio);
	}

	resp = query_responder(cbio, host, path, headers, req, req_timeout);
	if (resp == NULL)
		BIO_printf(bio_err, "Error querying OCSP responder\n");
	end: BIO_free_all(cbio);
	SSL_CTX_free(ctx);
	return resp;
}
std::string cert_value2str(X509_NAME *subject) {
	if (!subject) {
		return "";
	}
	int subject_position = X509_NAME_get_index_by_NID(subject, NID_commonName,
			0);
	X509_NAME_ENTRY *entry =
			subject_position == -1 ?
					NULL : X509_NAME_get_entry(subject, subject_position);
	ASN1_STRING *d = X509_NAME_ENTRY_get_data(entry);
	return std::string((char*) ASN1_STRING_data(d), ASN1_STRING_length(d));
}

OCSP_RESPONSE *query_responder(BIO *cbio, const char *host, const char *path,
		const STACK_OF(CONF_VALUE) *headers, OCSP_REQUEST *req, int req_timeout)
{
	int fd;
	int rv;
	int i;
	int add_host = 1;
	OCSP_REQ_CTX *ctx = NULL;
	OCSP_RESPONSE *rsp = NULL;
	fd_set confds;
	struct timeval tv;

	if (req_timeout != -1)
	BIO_set_nbio(cbio, 1);

	rv = BIO_do_connect(cbio);

	if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
		BIO_puts(bio_err, "Error connecting BIO\n");
		return NULL;
	}

	if (BIO_get_fd(cbio, &fd) < 0) {
		BIO_puts(bio_err, "Can't get connection fd\n");
		goto err;
	}

	if (req_timeout != -1 && rv <= 0) {
		FD_ZERO(&confds);
		openssl_fdset(fd, &confds);tv.tv_usec = 0;
		tv.tv_sec = req_timeout;
		rv = select(fd + 1, NULL, (fd_set *)&confds, NULL, &tv);
		if (rv == 0) {
			BIO_puts(bio_err, "Timeout on connect\n");
			return NULL;
		}
	}

	ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
	if (ctx == NULL)
	return NULL;

	for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
		CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
		if (add_host == 1 && strcasecmp("host", hdr->name) == 0)
		add_host = 0;
		if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
		goto err;
	}

	if (add_host == 1 && OCSP_REQ_CTX_add1_header(ctx, "Host", host) == 0)
	goto err;

	if (!OCSP_REQ_CTX_set1_req(ctx, req))
	goto err;

	for (;;) {
		rv = OCSP_sendreq_nbio(&rsp, ctx);
		if (rv != -1)
		break;
		if (req_timeout == -1)
		continue;
		FD_ZERO(&confds);
		openssl_fdset(fd, &confds);
		tv.tv_usec = 0;
		tv.tv_sec = req_timeout;
		if (BIO_should_read(cbio)) {
			rv = select(fd + 1, (fd_set *)&confds, NULL, NULL, &tv);
		} else if (BIO_should_write(cbio)) {
			rv = select(fd + 1, NULL, (fd_set *)&confds, NULL, &tv);
		} else {
			BIO_puts(bio_err, "Unexpected retry condition\n");
			goto err;
		}
		if (rv == 0) {
			BIO_puts(bio_err, "Timeout on request\n");
			break;
		}
		if (rv == -1) {
			BIO_puts(bio_err, "Select error\n");
			break;
		}

	}
	err:
	OCSP_REQ_CTX_free(ctx);

	return rsp;
}
bool ocsp_verify(SSL* ssl, X509* cert, std::string & url) {
	OCSP_RESPONSE *resp = NULL;
	unsigned char *rspder = NULL;
	int rspderlen;
	int ret;
	ret = get_ocsp_resp_from_responder(ssl, &resp);
	if (ret != SSL_TLSEXT_ERR_OK)
		goto err;

	rspderlen = i2d_OCSP_RESPONSE(resp, &rspder);
	if (rspderlen <= 0)
		goto err;

	SSL_set_tlsext_status_ocsp_resp(ssl, rspder, rspderlen);
	BIO_puts(bio_err, "cert_status: ocsp response sent:\n");
	//OCSP_RESPONSE_print(bio_err, resp, 2);

	ret = SSL_TLSEXT_ERR_OK;

	err: if (ret != SSL_TLSEXT_ERR_OK)
		ERR_print_errors(bio_err);

	OCSP_RESPONSE_free(resp);

	return ret == SSL_TLSEXT_ERR_OK;
}

int get_ocsp_resp_from_responder(SSL *s, OCSP_RESPONSE **resp) {
	char *host = NULL, *port = NULL, *path = NULL;
	int use_ssl;
	STACK_OF(OPENSSL_STRING) * aia = NULL;
	X509 *x = NULL;
	X509_STORE_CTX *inctx = NULL;
	X509_OBJECT *obj;
	OCSP_REQUEST *req = NULL;
	OCSP_CERTID *id = NULL;
	STACK_OF(X509_EXTENSION) * exts;
	int ret = SSL_TLSEXT_ERR_NOACK;
	int i;

	/* Build up OCSP query from server certificate */
	x = SSL_get_certificate(s);
	aia = X509_get1_ocsp(x);
	if (aia != NULL) {
		if (!OCSP_parse_url(sk_OPENSSL_STRING_value(aia, 0), &host, &port,
				&path, &use_ssl)) {
			BIO_puts(bio_err, "cert_status: can't parse AIA URL\n");
			goto err;
		}
		BIO_printf(bio_err, "cert_status: AIA URL: %s\n",
				sk_OPENSSL_STRING_value(aia, 0));
	}

	inctx = X509_STORE_CTX_new();
	if (inctx == NULL)
		goto err;
	if (!X509_STORE_CTX_init(inctx, SSL_CTX_get_cert_store(SSL_get_SSL_CTX(s)),
	NULL, NULL))
		goto err;
	obj = X509_STORE_CTX_get_obj_by_subject(inctx, X509_LU_X509,
			X509_get_issuer_name(x));
	if (obj == NULL) {
		BIO_puts(bio_err,
				"cert_status: Can't retrieve issuer certificate of the following name:\n");
		BIO_puts(bio_err, cert_value2str(X509_get_issuer_name(x)).c_str());
		BIO_puts(bio_err, "\n");
		goto done;
	}
	id = OCSP_cert_to_id(NULL, x, X509_OBJECT_get0_X509(obj));
	X509_OBJECT_free(obj);
	if (id == NULL)
		goto err;
	req = OCSP_REQUEST_new();
	if (req == NULL)
		goto err;
	if (!OCSP_request_add0_id(req, id))
		goto err;
	id = NULL;
	/* Add any extensions to the request */
	SSL_get_tlsext_status_exts(s, &exts);
	for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
		if (!OCSP_REQUEST_add_ext(req, ext, -1))
			goto err;
	}
	*resp = process_responder(req, host, path, port, use_ssl, NULL, -1);
	if (*resp == NULL) {
		BIO_puts(bio_err, "cert_status: error querying responder\n");
		goto done;
	}

	ret = SSL_TLSEXT_ERR_OK;
	goto done;

	err: ret = SSL_TLSEXT_ERR_ALERT_FATAL;
	done:
	/*
	 * If we parsed aia we need to free; otherwise they were copied and we
	 * don't
	 */
	if (aia != NULL) {
		OPENSSL_free(host);
		OPENSSL_free(path);
		OPENSSL_free(port);
		X509_email_free(aia);
	}
	OCSP_CERTID_free(id);
	OCSP_REQUEST_free(req);
	X509_STORE_CTX_free(inctx);
	return ret;
}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx) {
	int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	int err = X509_STORE_CTX_get_error(x509_ctx);

	/*
	 * Retrieve the pointer to the SSL of the connection currently treated
	 * and the application specific data stored into the SSL object.
	 */
	SSL * ssl = (SSL *) X509_STORE_CTX_get_ex_data(x509_ctx,
			SSL_get_ex_data_X509_STORE_CTX_idx());

	X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	std::vector<std::string> urls = ocsp_urls(cert);

	bool ocsp_verified = !urls.empty() && ocsp_verify(ssl, cert, urls[0]);

	X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
	X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
	std::cout << depth << " Subject Name: " << cert_value2str(sname)
			<< " Issuer: " << cert_value2str(iname) << std::endl;

	if (preverify == 0) {
		std::cerr << "Peer certificate chain verification failed! "
				<< std::endl;
		std::cerr << "Subject Name: " << cert_value2str(sname) << " Issuer: "
				<< cert_value2str(iname) << std::endl;
		std::cerr << "Error: " << X509_verify_cert_error_string(err)
				<< std::endl;
	}
	if (!urls.empty() && !ocsp_verified) {
		std::cerr << "Peer certificate chain OCSP verification failed! "
				<< std::endl;
		std::cerr << "Subject Name: " << cert_value2str(sname) << " Issuer: "
				<< cert_value2str(iname) << std::endl;
		std::cerr << "Error: " << X509_verify_cert_error_string(err)
				<< std::endl;
		return 0;
	}
	return preverify;
}

void init_openssl() {
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	ERR_load_crypto_strings();
}

void cleanup_openssl() {
	EVP_cleanup();
}

void ShowCerts(SSL* ssl) {
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if (cert != NULL) {
		printf("Peer certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);

		free(line);
		X509_free(cert);
	} else
		printf("No certificates.\n");
}
SSL_CTX * create_ssl_client_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	method = SSLv23_client_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void sslError(SSL *ssl, int received) {
	const int err = SSL_get_error(ssl, received);
	// const int st = ERR_get_error();
	if (err == SSL_ERROR_NONE) {
		std::cout << "SSL_ERROR_NONE:" << SSL_ERROR_NONE << std::endl;
// SSL_shutdown(ssl);
	} else if (err == SSL_ERROR_WANT_READ) {
		std::cout << "SSL_ERROR_WANT_READ:" << SSL_ERROR_WANT_READ << std::endl;
		SSL_shutdown(ssl);
//kill(getpid(), SIGKILL);
		pthread_exit(NULL);
	} else if (SSL_ERROR_SYSCALL) {
		std::cout << "SSL_ERROR_SYSCALL:" << SSL_ERROR_SYSCALL << std::endl;
		SSL_shutdown(ssl);
//kill(getpid(), SIGKILL);
		pthread_exit(NULL);
	}
}
SSL_CTX * create_ssl_server_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	method = SSLv23_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}
void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
	if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
		ERR_print_errors_fp(stderr);

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		ERR_print_errors_fp(stderr);

	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}

	SSL_CTX_set_ecdh_auto(ctx, 1);
	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	printf("Loaded Certificates Successfully!\n");
}

SSL_CTX * initSSLServerCtx(const char * cert_path, const char * pvtKey_path) {
	// Initialize ssl

	SSL_library_init();

	init_openssl();
	SSL_CTX * ctx = create_ssl_server_context();
	LoadCertificates(ctx, cert_path, pvtKey_path);

	return ctx;
}

SSL_CTX * initSSLClientCtx(const char * cert_path, const char * pvtKey_path) {
	// Initialize ssl
	SSL_library_init();

	init_openssl();
	SSL_CTX*ctx = create_ssl_client_context();

	LoadCertificates(ctx, cert_path, pvtKey_path);

	return ctx;
}
static void nodes_print(const char *name, STACK_OF(X509_POLICY_NODE) *nodes) {
	X509_POLICY_NODE *node;
	int i;

	BIO_printf(bio_err, "%s Policies:", name);
	if (nodes) {
		BIO_puts(bio_err, "\n");
		for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
			node = sk_X509_POLICY_NODE_value(nodes, i);
			X509_POLICY_NODE_print(bio_err, node, 2);
		}
	} else {
		BIO_puts(bio_err, " <empty>\n");
	}
}
void policies_print(X509_STORE_CTX *ctx) {
	X509_POLICY_TREE *tree;
	int explicit_policy;
	tree = X509_STORE_CTX_get0_policy_tree(ctx);
	explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

	BIO_printf(bio_err, "Require explicit Policy: %s\n",
			explicit_policy ? "True" : "False");

	nodes_print("Authority", X509_policy_tree_get0_policies(tree));
	nodes_print("User", X509_policy_tree_get0_user_policies(tree));
}

X509_STORE *setup_verify(const char *CAfile, const char *CApath, int noCAfile,
		int noCApath) {
	X509_STORE *store = X509_STORE_new();
	X509_LOOKUP *lookup;

	if (store == NULL)
		goto end;

	if (CAfile != NULL || !noCAfile) {
		lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
		if (lookup == NULL)
			goto end;
		if (CAfile) {
			if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
				BIO_printf(bio_err, "Error loading file %s\n", CAfile);
				goto end;
			}
		} else {
			X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
		}
	}

	if (CApath != NULL || !noCApath) {
		lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
		if (lookup == NULL)
			goto end;
		if (CApath) {
			if (!X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM)) {
				BIO_printf(bio_err, "Error loading directory %s\n", CApath);
				goto end;
			}
		} else {
			X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
		}
	}

	ERR_clear_error();
	return store;
	end: X509_STORE_free(store);
	return NULL;
}

void initCAStore(SSL_CTX*ctx, const char* ca_cert_file_path) {
	store = setup_verify(ca_cert_file_path, 0, 0, 1);
	SSL_CTX_set_cert_store(ctx, store);
}

void verifyOwnCert(SSL_CTX*ctx, SSL * ssl) {
	X509 * own_cert = SSL_CTX_get0_certificate(ctx);
	X509_STORE_CTX *vrfy_ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(vrfy_ctx, store, own_cert, NULL);
	int ret = X509_verify_cert(vrfy_ctx);

	BIO_printf(bio_err, "Verification return code: %d\n", ret);
	if (ret == 0 || ret == 1) {
		BIO_printf(bio_err, "Verification result text: %s\n",
				X509_verify_cert_error_string(
						X509_STORE_CTX_get_error(vrfy_ctx)));
	}
	std::vector<std::string> urls = ocsp_urls(own_cert);
	if (!urls.empty()) {
		bool verified = ocsp_verify(ssl, own_cert, urls[0]);
		if (!verified) {
			BIO_printf(bio_err, "OCSP Verification failed.\n");
			abort();
		} else {
			BIO_printf(bio_err, "OCSP Verification Success.\n");
		}
	}
	X509_STORE_CTX_free(vrfy_ctx);
}

}
