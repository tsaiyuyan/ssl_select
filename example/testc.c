/** @example testc.c
 * test try connect to google web with blocking or nonblocking mode
 * Examples 1
 */
#include "ssl_select.h"
#include <arpa/inet.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

const char* http_req = "GET / HTTP/1.0\r\n\r\n";

int hostname_to_ip(char* hostname, char* ip)
{
	struct hostent* he;
	struct in_addr** addr_list;
	int i;

	if ((he = gethostbyname(hostname)) == NULL) {
		// get the host info
		herror("gethostbyname");
		return 1;
	}

	addr_list = (struct in_addr**)he->h_addr_list;
	for (i = 0; addr_list[i] != NULL; i++) {
		//Return the first one;
		strcpy(ip, inet_ntoa(*addr_list[i]));
		return 0;
	}
	return 1;
}

int tcp_connect(char* addr, char* port)
{
	struct addrinfo *result, *ptr;
	struct addrinfo hints;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;
	int ret;
	int sk;

	ret = getaddrinfo(addr, port, &hints, &result);
	if (ret != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		if (ptr->ai_family != AF_INET && ptr->ai_family != AF_INET6) {
			printf("unkown ai_family\n");
			continue;
		}
		sk = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (sk < 0) {
			printf("create socket failed(%d)\n", sk);
			continue;
		}
		printf("create socket(%d)\n", sk);

		ret = connect(sk, ptr->ai_addr, ptr->ai_addrlen);
		if (ret < 0 && errno != EINPROGRESS) {
			printf("cannot connect %s\n", strerror(errno));
			close(sk);
			sk = -1;
			continue;
		} else if (ret == 0) {
			printf("connected successfully on %d\n", sk);
			break;
		}
	}
	freeaddrinfo(result);
	return sk;
}

#define ssl_perror(tag)                                                 \
	do {                                                                \
		ssl_errno_str(_ssl, ssl_errno, ssl_errstr, sizeof(ssl_errstr)); \
		printf(tag ": %s\n", ssl_errstr);                               \
	} while (0)

ssl_info* ssl_connect(int sk)
{
	if (sk < 0)
		return NULL;

	const SSL_METHOD* method = SSLv23_method();
	char ssl_errstr[256];
	int ssl_errno;
	ssl_info* _ssl = sslinfo_alloc();
	_ssl->sk = sk;
	_ssl->ctx = SSL_CTX_new(method);
	_ssl->ssl = SSL_new(_ssl->ctx);
	printf("using ctx@%p\n", _ssl->ctx);

	do {
		if (SSL_set_fd(_ssl->ssl, sk) == 0) {
			printf("SSL_set_fd failed\n");
			break;
		}
		//printf("SSL_set_fd success\n");

		if (ssl_connect_simple(_ssl, 3000, &ssl_errno) != 1) {
			ssl_perror("ssl_connect_simple\n");
			break;
		}
		return _ssl;
	} while (0);

	free(_ssl);
	return NULL;
}

int ssl_nonblocking_test(int sk)
{
	if (sk < 0)
		return -1;

	__set_block(sk);
	ssl_info* _ssl = ssl_connect(sk);
	if (!_ssl)
		return -2;
	__set_nonblock(sk);

	int cnt = 0;
	int ssl_errno;
	char ssl_errstr[256];
	do {
		// send message
		if (!ssl_send_direct(_ssl, (void*)http_req, strlen(http_req), &ssl_errno)) {
			ssl_perror("ssl_send_direct");
			break;
		}

		fd_set rfds, efds, wfds;
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);

		struct timeval tv = { 3, 0 }, *tv_ptr = &tv;
		struct timeval zerotv;
		timerclear(&zerotv);

		char recv_buf[1024] = "";
		int rlen = sizeof(recv_buf) - 1;

		int maxfd = _ssl->sk;

#define printf_flag(obj) printf(#obj "r: %d, w: %d\n", obj.read, obj.write)
		printf_flag(_ssl->accept);
		printf_flag(_ssl->connect);
		printf_flag(_ssl->send);
		printf_flag(_ssl->recv);

		while (1) {
			ssl_set_fds(_ssl, maxfd, &rfds, &wfds);

			int len = ssl_recv_direct(_ssl, recv_buf, rlen, &ssl_errno);
			//printf_flag(_ssl->recv);
			if (len == SSL_OPS_SELECT) {
				printf("ssl_recv_direct1: SSL_OPS_SELECT\n");
				ssl_set_fds(_ssl, maxfd, &rfds, &wfds);

				int ret = select(maxfd + 1, &rfds, &wfds, &efds, tv_ptr);
				if (ret == 0) {
					printf("select timeout \n");
					continue;
				} else if (ret < 0) {
					perror("select");
					break;
				}

				int tasks = ssl_handle_fds(_ssl, &rfds, &wfds);
				if (tasks & invoke_ssl_recv) {

				} else {
					printf("tasks = %d\n", tasks);
					break;
				}
			} else if (len <= 0) {
				ssl_perror("ssl_recv_direct len <= 0 ");
				break;
			} else {
				recv_buf[len] = 0;
#ifdef PRINTF_RECV_BUF
				printf("%s", recv_buf);
#else
				printf("recv(%d)\n", len);
#endif
				cnt += len;
			}
		}
	} while (0);

	SSL_shutdown(_ssl->ssl);
	SSL_free(_ssl->ssl);
	close(_ssl->sk);
	free(_ssl);

	return cnt;
}

int ssl_blocking_test(int sk)
{
	if (sk < 0)
		return -1;

	__set_block(sk);
	ssl_info* _ssl = ssl_connect(sk);
	if (!_ssl)
		return -2;

	int cnt = 0;
	int ssl_errno;
	char ssl_errstr[256];

	do {
		// send message
		if (!ssl_send_direct(_ssl, (void*)http_req, strlen(http_req), &ssl_errno)) {
			ssl_perror("ssl_send_direct");
			break;
		}

		char recv_buf[1024] = "";
		int rlen = sizeof(recv_buf) - 1;
		while (1) {
			int len = ssl_recv_simple(_ssl, recv_buf, rlen, 3000, &ssl_errno);
			if (len > 0) {
				recv_buf[len] = 0;
#ifdef PRINTF_RECV_BUF
				printf("%s", recv_buf);
#else
				printf("recv(%d)\n", len);
#endif
				cnt += len;
			} else {
				ssl_perror("ssl_recv_direct");
				break;
			}
		}
	} while (0);

	SSL_shutdown(_ssl->ssl);
	SSL_free(_ssl->ssl);
	close(_ssl->sk);
	free(_ssl);
	return cnt;
}

int main(int argc, char* argv[])
{
	char ip[1024];
	char* hostname = NULL;

	if (argc == 2)
		hostname = argv[1];
	else if (argc == 1)
		hostname = "www.google.com";
	else {
		printf("usage:\n"
			   "\twebclient\n"
			   "\twebclient www.yahoo.com\n");
		return -1;
	}

	// get google ip
	hostname_to_ip(hostname, ip);
	printf("%s resolved to %s\n", hostname, ip);

	printf("======= ssl_nonblocking ==========\n");
	// https test
	int ret;
	ret = ssl_nonblocking_test(tcp_connect(ip, "443"));
	printf("https_nbk_test, total_len = %d\n", ret);

	printf("\n======= ssl_blocking ==========\n");
	ret = ssl_blocking_test(tcp_connect(ip, "443"));
	printf("https_bk_test, total_len = %d\n", ret);
	return 0;
}