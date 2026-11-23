# ARGUS analysis image: scores telemetry collected on Windows, offline. Never touches the host it runs on.
# by HaiND from the Post and Telecommunication Institute of Technology
FROM python:3.12-slim
LABEL org.opencontainers.image.title="ARGUS" \
      org.opencontainers.image.description="Detect-only threat hunting engine (MITRE ATT&CK). by HaiND from the Post and Telecommunication Institute of Technology" \
      org.opencontainers.image.source="https://github.com/Haind03/argus" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="HaiND"
COPY dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl yara-python && rm -f /tmp/*.whl \
 && useradd --create-home --uid 10001 argus
USER argus
WORKDIR /work
ENTRYPOINT ["argus"]
CMD ["--help"]
