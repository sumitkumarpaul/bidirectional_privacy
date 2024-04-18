
U_DU_PORT ?= 1235
U_DU_CERT ?= materials/sample_du_cert.pem
U_DU_PRI_KEY ?= materials/sample_du_pri_key.pem

all:
	gcc -O0 -Wall -Wextra -o u_data_user ./src/u_data_user_main.c -lssl -lcrypto

clean:
	rm -rf *.o
	rm -rf u_data_user

test:
	@echo Running the program as:./u_data-user "$(U_DU_PORT)" "$(U_DU_CERT)" "$(U_DU_PRI_KEY)"
	./u_data_user "$(U_DU_PORT)" "$(U_DU_CERT)" "$(U_DU_PRI_KEY)"
	
