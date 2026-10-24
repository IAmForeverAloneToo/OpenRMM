# Build-time only: wixl (msitools) turns installer/openrmm-agent.wxs and the
# built Windows programs into the agent MSI. Reviewed in docs/DEPENDENCIES.md.
# Nothing from this image reaches the server image or a managed device except
# the MSI it writes.
FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wixl=0.106+repack-2 wixl-data=0.106+repack-2 \
    && rm -rf /var/lib/apt/lists/*
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["wixl"]
