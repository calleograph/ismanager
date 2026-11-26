FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -o Acquire::Retries=3 update && apt-get install -y --no-install-recommends samba-ad-dc samba-ad-provision samba-vfs-modules openssl && rm -rf /var/lib/apt/lists/*
COPY setup.sh /usr/local/bin/prepare-test-domain
CMD ["/bin/bash", "/usr/local/bin/prepare-test-domain"]
