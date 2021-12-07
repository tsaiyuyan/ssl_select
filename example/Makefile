CFLAGS = -I../ -lssl -lcrypto
#-D PRINTF_RECV_BUF

CC = gcc -std=gnu11 -Wall -Werror
#
all: webserver.out webclient.out

ssl_select.o : ../ssl_select.c
	$(CC) -c $< -o $@ $(CFLAGS)

%.o : %.c
	$(CC) -c $< -o $@ $(CFLAGS)

webclient.out: testc.o ssl_select.o
	$(CC) $^ -o $@ $(CFLAGS)

webserver.out: tests.o ssl_select.o
	$(CC) $^ -o $@  $(CFLAGS)

clean:
	rm -f ./*.o
	rm -f ./*.out

# test https/http server, by using curl tool.
tests:

	@echo '********** test http server *************************************'
	curl http://127.0.0.1:8080

	@echo '********** test https server with ca in insecure mode ***********'
	curl https://127.0.0.1:8443 --cacert ./cert/ca.pem -k

	@echo '*********  test https server without ca in secure mode **********'
	curl https://127.0.0.1:8443 -k

	@echo '*********  fail_test https server in secure mode ****************'
	curl https://127.0.0.1:8443

# test try connect to google web with blocking or nonblocking mode
testc:
	@echo '********** test google https server *****************************'
	./webclient.out
