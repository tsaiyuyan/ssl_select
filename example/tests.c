/** @example tests.c
 * create simple https/http server
 * Examples 2
 */
#include "ssl_select.h"
#include <arpa/inet.h>
#include <error.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

const char* http_resp = "HTTP/1.0 200 OK\r\n"
						"Content-Type: text/html\r\n"
						"\r\n"
						"<html><head></head><body>simple server</body></html>\r\n";

#define HTTPS_SERVICE_PORT "8443"
#define HTTP_SERVICE_PORT "8080"

#define ssl_perror(tag)                                                 \
	do {                                                                \
		ssl_errno_str(_ssl, ssl_errno, ssl_errstr, sizeof(ssl_errstr)); \
		printf(tag ": %s\n", ssl_errstr);                               \
	} while (0)

static SSL_CTX* m_ctx = NULL;
static ssl_pwd_data m_ssl_pwd_data;

int global_ssl_init()
{
	if (m_ctx) {
		printf("error using this functions %s\n", __func__);
		exit(-1);
	}
	init_ssl_lib();
	// ssl config load
	m_ctx = initialize_ctx("../certs/rootCA.pem",
		"../certs/ca.pem",
		"",
		&m_ssl_pwd_data);
	printf("create ctx @%p\n", m_ctx);
	return 0;
}

int start_tcp_server(const char* port)
{
	int listenfd;
	struct addrinfo hints, *res, *p;

	// getaddrinfo for host
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(NULL, port, &hints, &res) != 0) {
		perror("getaddrinfo() error");
		exit(1);
	}
	// socket and bind
	for (p = res; p != NULL; p = p->ai_next) {
		int option = 1;
		listenfd = socket(p->ai_family, p->ai_socktype, 0);
		setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
		setsockopt(listenfd, IPPROTO_TCP, TCP_NODELAY, (char*)&option, sizeof(int));

		if (listenfd == -1)
			continue;
		if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
			break;
	}
	if (p == NULL) {
		perror("socket() or bind()");
		exit(1);
	}

	freeaddrinfo(res);

	// listen for incoming connections
	if (listen(listenfd, 1000000) != 0) {
		perror("listen() error");
		exit(1);
	}
	return listenfd;
}

ssl_info* tls_accept(int sk)
{
	if (sk < 0)
		return NULL;

	if (!m_ctx)
		return NULL;

	ssl_info* _ssl = sslinfo_alloc();
	if (!_ssl)
		return NULL;

	int ssl_errno;
	char ssl_errstr[256] = "";
	_ssl->sk = sk;
	_ssl->ctx = m_ctx;
	_ssl->ssl = SSL_new(m_ctx);
	//__set_nonblock(_ssl->sk);
	do {
		SSL_set_fd(_ssl->ssl, _ssl->sk);
		if (ssl_accept_simple(_ssl, 3000, &ssl_errno) != 1) {
			ssl_perror("ssl_accept_simple");
			printf("ssl_accept_simple fail\n");
			break;
		}

		printf("ssl_accept_simple success\n");
		return _ssl;
	} while (0);

	free(_ssl);
	return NULL;
}

int simple_https_server()
{
	int ssl_errno = 0;
	char ssl_errstr[256] = "";
	char* port = HTTPS_SERVICE_PORT;
	pid_t childpid;
	int sk = start_tcp_server(port);
	printf("listen(%s) = %d...\n", port, sk);

	struct sockaddr_in clientaddr;
	while (1) {

		socklen_t addrlen = sizeof(clientaddr);
		int clientfd = accept(sk, (struct sockaddr*)&clientaddr, &addrlen);
		if (clientfd < 0) {
			perror("accept:");
			continue;
		}
		printf("connection accepted from %s:%d\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));
		__set_nonblock(clientfd);
		ssl_info* _ssl = tls_accept(clientfd);
		if (!_ssl) {
			close(clientfd);
			continue;
		}

		if ((childpid = fork()) == 0) {
			close(sk);
			int retry = 0;
			int cnt = 0;
			char recv_buf[256] = "";
			int rlen = sizeof(recv_buf) - 1;
			//ssl
			while (1) {
				int len = ssl_recv_direct(_ssl, recv_buf, rlen, &ssl_errno);
				if (len > 0) {
					recv_buf[len] = 0;
					//printf("%s",recv_buf);
					cnt += len;
					// easy https check
					if (strstr(recv_buf, "\r\n\r\n")) {
						// send message
						if (!ssl_send_direct(_ssl, (void*)http_resp, strlen(http_resp), &ssl_errno)) {
							ssl_perror("ssl_send_direct");
							break;
						}
					} else {
						printf("http error quesy\n");
						break;
					}
				} else {
					ssl_perror("ssl_recv_direct");
					if (cnt > 0 || retry > 3)
						break;
					else
						usleep(100000);
					retry++;
				}
			}
			printf("ssl_cnt (%d), finish.\n", cnt);
			__set_block(_ssl->sk);
			SSL_shutdown(_ssl->ssl);
			free(_ssl);

			close(clientfd);
			exit(0);
		} else if (childpid < 0) {
			perror("fork()");
			close(clientfd);
		}
	}
	return 0;
}

int simple_http_server()
{
	pid_t childpid;
	char* port = HTTP_SERVICE_PORT;

	int sk = start_tcp_server(HTTP_SERVICE_PORT);
	if (sk < 0) {
		perror("listen:");
		exit(1);
	}
	printf("listen(%s) = %d...\n", port, sk);

	struct sockaddr_in clientaddr;
	while (1) {
		socklen_t addrlen = sizeof(clientaddr);
		int clientfd = accept(sk, (struct sockaddr*)&clientaddr, &addrlen);
		if (clientfd < 0) {
			perror("accept:");
			continue;
		}
		printf("connection accepted from %s:%d\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));
		if ((childpid = fork()) == 0) {
			close(sk);
			int cnt = 0;
			char recv_buf[256] = "";
			int rlen = sizeof(recv_buf) - 1;
			//ssl
			while (1) {
				int len = recv(clientfd, recv_buf, rlen, 0);
				if (len <= 0) {
					printf("disconnected from %s:%d\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));
					break;
				} else {
					recv_buf[len] = 0;
					cnt += len;
					//printf("%s", recv_buf);
					int slen = strlen(http_resp);
					len = send(clientfd, http_resp, slen, 0);

					printf("rx(%d), tx(%d), finish\n", cnt, len);
					//printf("slen (%d), len(%d)\n", slen, len);
					bzero(recv_buf, sizeof(recv_buf));
					shutdown(clientfd, SHUT_RDWR);
				}
			}
			close(clientfd);
			exit(0);
		} else if (childpid < 0) {
			perror("fork()");
			close(clientfd);
		}
	}
	return 0;
}

int main(int argc, char* argb[])
{
	global_ssl_init();
	if (fork() == 0) {
		printf("start https server...\n");
		simple_https_server();
		exit(0);
	}
	printf("start http server...\n");
	simple_http_server();
	return 0;
}
