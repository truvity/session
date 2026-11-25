# The image of session-echo, the test backend of a deployed conformance site (decision 0029). .github/workflows/image.yaml builds
# the executable in its job with no token, beside session's, and copies it here: the build context holds
# linux/<arch>/session-echo for each platform, and this file has no RUN.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETPLATFORM
LABEL org.opencontainers.image.title="session-echo" \
      org.opencontainers.image.description="session-echo: the test backend of a conformance site of session; it echoes every request as JSON" \
      org.opencontainers.image.source="https://github.com/truvity/session" \
      org.opencontainers.image.licenses="MIT"
COPY --chmod=0555 ${TARGETPLATFORM}/session-echo /usr/bin/session-echo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/bin/session-echo"]
