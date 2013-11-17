check: clean process_pcap compare_md5

clean:
	@echo "*** Cleaning decapsulated pcap files..."
	-rm -vf ./3des-cbc_hmac-sha1/3des-cbc_hmac-sha1.cap.output 
	-rm -vf ./3des-cbc_null/3des-cbc_null.cap.output 
	-rm -vf ./aes192-cbc_hmac-sha1/aes192-cbc_hmac-sha1.cap.output 
	-rm -vf ./aes256-cbc_hmac-sha1/aes256-cbc_hmac-sha1.cap.output 
	-rm -vf ./aes-cbc_hmac-sha1/aes-cbc_hmac-sha1.cap.output 
	-rm -vf ./des-cbc_hmac-md5/des-cbc_hmac-md5.cap.output 
	-rm -vf ./null_hmac-md5/null_hmac-md5.cap.output 

process_pcap: 
	@echo "*** Processing 3des-cbc_hmac-sha1.cap..."
	../../src/ipdecap \
	-i ./3des-cbc_hmac-sha1/3des-cbc_hmac-sha1.cap \
	-o ./3des-cbc_hmac-sha1/3des-cbc_hmac-sha1.cap.output \
	-c ./3des-cbc_hmac-sha1/3des-cbc_hmac-sha1.cap.conf
	
	@echo "*** Processing 3des-cbc_null.cap..."
	../../src/ipdecap \
	-i ./3des-cbc_null/3des-cbc_null.cap \
	-o ./3des-cbc_null/3des-cbc_null.cap.output \
	-c ./3des-cbc_null/3des-cbc_null.cap.conf
	
	@echo "*** Processing aes192-cbc_hmac-sha1.cap..."
	../../src/ipdecap \
	-i ./aes192-cbc_hmac-sha1/aes192-cbc_hmac-sha1.cap \
	-o ./aes192-cbc_hmac-sha1/aes192-cbc_hmac-sha1.cap.output \
	-c ./aes192-cbc_hmac-sha1/aes192-cbc_hmac-sha1.cap.conf
	
	@echo "*** Processing aes256-cbc_hmac-sha1.cap..."
	../../src/ipdecap \
	-i ./aes256-cbc_hmac-sha1/aes256-cbc_hmac-sha1.cap \
	-o ./aes256-cbc_hmac-sha1/aes256-cbc_hmac-sha1.cap.output \
	-c ./aes256-cbc_hmac-sha1/aes256-cbc_hmac-sha1.cap.conf
	
	@echo "*** Processing aes-cbc_hmac-sha1.cap..."
	../../src/ipdecap \
	-i ./aes-cbc_hmac-sha1/aes-cbc_hmac-sha1.cap \
	-o ./aes-cbc_hmac-sha1/aes-cbc_hmac-sha1.cap.output \
	-c ./aes-cbc_hmac-sha1/aes-cbc_hmac-sha1.cap.conf
	
	@echo "*** Processing des-cbc_hmac-md5.cap..."
	../../src/ipdecap \
	-i ./des-cbc_hmac-md5/des-cbc_hmac-md5.cap \
	-o ./des-cbc_hmac-md5/des-cbc_hmac-md5.cap.output \
	-c ./des-cbc_hmac-md5/des-cbc_hmac-md5.cap.conf
	
	@echo "*** Processing null_hmac-md5.cap..."
	../../src/ipdecap \
	-i ./null_hmac-md5/null_hmac-md5.cap \
	-o ./null_hmac-md5/null_hmac-md5.cap.output \
	-c ./null_hmac-md5/null_hmac-md5.cap.conf

compare_md5:
	@echo "*** Comparing checksums..."
	md5sum -c esp.md5
	

.PHONY = check
