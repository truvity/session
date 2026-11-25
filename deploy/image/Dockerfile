# The image of session (decision 0028). .github/workflows/image.yaml builds the executables in a job with no token and copies
# them here in a job that holds the packages permission: the build context holds linux/<arch>/session for each platform, and
# this file has no RUN, so nothing is built where the credential is.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETPLATFORM
LABEL org.opencontainers.image.title="session" \
      org.opencontainers.image.description="session: browser sessions in front of a site, as the external authorisation of its proxy" \
      org.opencontainers.image.source="https://github.com/truvity/session" \
      org.opencontainers.image.licenses="MIT"
COPY --chmod=0555 ${TARGETPLATFORM}/session /usr/bin/session
USER 65532:65532
ENTRYPOINT ["/usr/bin/session"]
CMD ["serve"]
