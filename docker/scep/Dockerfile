FROM eclipse-temurin:17-jre-noble@sha256:ad806840ae514b83d3d8e3a00a5c1b7302fb0a6ae02bbbaf8a8bf1ffdf5367c6 AS runtime

FROM runtime AS server

WORKDIR /app
RUN useradd --system --uid 10001 --user-group scep \
    && mkdir /app/depot \
    && chown scep:scep /app/depot

COPY scep-server/target/scep-server-1.0.0-exec.jar /app/scep-server.jar

USER scep
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/scep-server.jar"]

FROM runtime AS client

WORKDIR /work
COPY scep-client/target/scep-client-1.0.0-exec.jar /app/scep-client.jar

ENTRYPOINT ["java", "-jar", "/app/scep-client.jar"]
CMD []
