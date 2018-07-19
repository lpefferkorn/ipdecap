check: clean process_pcap compare_md5

clean:
	@echo "*** Cleaning decapsulated pcap files..."
	-rm -vf *.cap.output

process_pcap:
	@echo "*** Processing icmp_ipip_tunnel.cap..."
	../../src/ipdecap -i icmp_ipip_tunnel.cap -o icmp_ipip_tunnel.cap.output
	@echo "*** Processing ipip_corrupted_header_length.pcapng..."
	../../src/ipdecap -i ipip_corrupted_header_length.pcapng -o ipip_corrupted_header_length.pcapng.output

compare_md5:
	@echo "*** Comparing checksums..."
	@MD5SUM@ -c ipip.md5


.PHONY = check
