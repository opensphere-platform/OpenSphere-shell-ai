FROM quay.io/opendatahub/mlmd-grpc-server:latest

USER 0
RUN mv /bin/metadata_store_server /bin/metadata_store_server.real
COPY metadata_store_server /bin/metadata_store_server
RUN chmod 0755 /bin/metadata_store_server
USER 65534
