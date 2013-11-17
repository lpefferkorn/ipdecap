check: clean process_pcap compare_md5

clean:
	@echo "*** Cleaning decapsulated pcap files..."
	-rm -vf *.cap.output

process_pcap: 
	@echo "*** Processing gre_version0.cap..."
	../../src/ipdecap -i gre_version0.cap -o gre_version0.cap.output

compare_md5:
	@echo "*** Comparing checksums..."
	md5sum -c gre.md5
	

.PHONY = check
