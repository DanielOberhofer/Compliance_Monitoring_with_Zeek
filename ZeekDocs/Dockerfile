FROM zeek/zeek:latest
COPY ./Zeek/ /
COPY ./1000_ICS.pcap /
RUN echo '@load policy/tuning/json-logs.zeek' >> /usr/local/zeek/share/zeek/site/local.zeek
