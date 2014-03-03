check: clean process_pcap compare_md5

clean:
	@echo "*** Cleaning decapsulated pcap files..."
	-rm -vf *.cap.output

process_pcap:
	@echo "*** Processing gre_version0.cap..."
	../../src/ipdecap -i icmp_ipip_tunnel.cap -o icmp_ipip_tunnel.cap.output

compare_md5:
	@echo "*** Comparing checksums..."
	@MD5SUM@ -c ipip.md5


.PHONY = check
