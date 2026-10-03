FROM eclipse-temurin:21-jre@sha256:cff19e6215689161eb6162c11b86b0c60ddf802164f2eaf48d570f8fb79a36c5

RUN apt-get update \
    && apt-get install -y --no-install-recommends libx11-6 libxext6 libxrender1 libxtst6 libxi6 libfreetype6 fontconfig fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Build context is prepared privately from the already verified vendor artifacts.
# Profiles, licenses, target credentials and Xauthority never enter the image.
COPY vendor/burpsuite-desktop-2026.9.jar /opt/burp/burpsuite-desktop-2026.9.jar
COPY vendor/burp-mcp-all.jar /opt/burp/burp-mcp-all.jar
RUN echo 'd6c80be60575b59a3097e939b1cf4acf2efd104c0f6ed05166753180365fc7fc  /opt/burp/burpsuite-desktop-2026.9.jar' | sha256sum -c - \
    && echo 'f93e434a9154fbb03bc9b20e46555fc901be57a80ec63d607d9cde192d27691c  /opt/burp/burp-mcp-all.jar' | sha256sum -c - \
    && chmod 0444 /opt/burp/*.jar
COPY entrypoint.sh /usr/local/bin/aegis-burp-runtime
RUN chmod 0555 /usr/local/bin/aegis-burp-runtime
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/aegis-burp-runtime"]
