timewindow=0.000500

ls Original_CICIDS2017_pcap/*.pcap | while read line; do editcap -w $timewindow $line ./WithoutDuplication_CICIDS2017_pcap/$(basename $line | sed 's/\.pcap/_without_duplication.pcap/'); done