check: clean process_pcap compare_md5

clean:
	@echo "*** Cleaning decapsulated pcap files..."
	-rm -vf *.cap.output

process_pcap:
	@echo "*** Processing icmp_802.1q_simple_layer.cap..."
	../../src/ipdecap -i icmp_802.1q_simple_layer.cap -o icmp_802.1q_simple_layer.cap.output
	@echo "*** Processing 802.1q_corrupted_packet.pcapng..."
	../../src/ipdecap -i 802.1q_corrupted_packet.pcapng -o 802.1q_corrupted_packet.pcapng.output

compare_md5:
	@echo "*** Comparing checksums..."
	@MD5SUM@ -c 802.1q.md5


.PHONY = check
