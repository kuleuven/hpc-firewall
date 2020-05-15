FROM centos:7
COPY ./hpc-firewall /usr/bin/hpc-firewall
RUN chmod +x /usr/bin/hpc-firewall
CMD /usr/bin/hpc-firewall
