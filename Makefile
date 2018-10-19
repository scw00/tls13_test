all:
	make tls13_early_data
	make tls13_psk_early_data
	make tls13_read_ex
tls13_early_data: tls13_early_data.cc tls13_util.cc
	g++ -o tls13_early_data tls13_early_data.cc tls13_util.cc -Wl,--rpath=/usr/local/openssl1.3/lib -I /usr/local/openssl1.3/include/ -L /usr/local/openssl1.3/lib/ -lcrypto -lssl -std=c++11 -g -O0	
tls13_psk_early_data: tls13_psk_early_data.cc tls13_util.cc 
	g++ -o tls13_psk_early_data tls13_psk_early_data.cc tls13_util.cc -Wl,--rpath=/usr/local/openssl1.3/lib -I /usr/local/openssl1.3/include/ -L /usr/local/openssl1.3/lib/ -lcrypto -lssl -std=c++11 -g -O0
tls13_read_ex: tls13_read_ex.cc tls13_util.cc
	g++ -o tls13_read_ex tls13_read_ex.cc tls13_util.cc -Wl,--rpath=/usr/local/openssl1.3/lib -I /usr/local/openssl1.3/include/ -L /usr/local/openssl1.3/lib/ -lcrypto -lssl -std=c++11 -g -O0
clean:
	rm -rf tls13_early_data
	rm -rf tls13_psk_early_data
