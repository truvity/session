# The Runtime Interface Emulator image of the fit spike: the provided.al2023 base image (it carries aws-lambda-rie),
# the Lambda Web Adapter as an extension, and cmd/fitapp as the function's bootstrap.
# Both images are pinned by digest. Build context: a directory with the binary `bootstrap` (see run.sh).
FROM public.ecr.aws/lambda/provided@sha256:4389209379db22f6caca72748d8cbfd86a470b5d0a9ff9efcdcf47198175edce
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter@sha256:17cfd08eff1dfea3f6a9a1e9c65fdac80aa4919b6085e746615530f43f57d2f1 /lambda-adapter /opt/extensions/lambda-adapter
COPY bootstrap /var/task/bootstrap
ENV AWS_LWA_PORT=8000 AWS_LWA_READINESS_CHECK_PATH=/healthz
CMD ["bootstrap"]
