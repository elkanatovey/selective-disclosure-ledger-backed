# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Builds the C++ selective-disclosure tool against the official CCF release and
# packages it together with the Python control plane.
#
# The CCF development RPM is downloaded from the microsoft/CCF release and
# checked against the SHA-256 digest that the GitHub release API publishes for
# that asset. A mismatch fails the build.

ARG CCF_VERSION="7.0.10"

# Pin a specific Azure Linux base image tag for reproducibility. This is the
# same base that the pinned scitt-ccf-ledger submodule builds against.
FROM mcr.microsoft.com/azurelinux/base/core:3.0.20260809 AS base

# Extract the package snapshot time that the CCF release was reproduced with,
# so that the build pulls the same dependency versions upstream used.
FROM base AS snapshot-extractor

ARG CCF_VERSION

RUN tdnf install -y ca-certificates jq && \
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/reproduce.json" \
    -o /tmp/reproduce.json && \
    jq -r '.tdnf_snapshottime' /tmp/reproduce.json > /tmp/tdnf_snapshottime

FROM base AS builder

ARG CCF_VERSION

COPY --from=snapshot-extractor /tmp/tdnf_snapshottime /tmp/tdnf_snapshottime

# Install the toolchain and the official CCF development package. The RPM is
# verified against the digest GitHub publishes for the release asset before it
# is installed; an empty or mismatched digest fails the build.
RUN TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime="${TDNF_SNAPSHOTTIME}" \
    ca-certificates \
    clang \
    cmake \
    git \
    jq \
    ninja-build \
    openssl-devel \
    rpm-build \
    tar && \
    CCF_RPM="ccf_devel_${CCF_VERSION//-/_}_x86_64.rpm" && \
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/${CCF_RPM}" \
    -o /tmp/ccf.rpm && \
    CCF_RPM_SHA256=$(curl -sSL "https://api.github.com/repos/microsoft/CCF/releases/tags/ccf-${CCF_VERSION}" \
    | jq -r --arg name "${CCF_RPM}" '.assets[] | select(.name == $name) | .digest | ltrimstr("sha256:")') && \
    [ -n "${CCF_RPM_SHA256}" ] && \
    echo "${CCF_RPM_SHA256}  /tmp/ccf.rpm" | sha256sum -c - && \
    tdnf install -y --snapshottime="${TDNF_SNAPSHOTTIME}" /tmp/ccf.rpm && \
    rm -f /tmp/ccf.rpm && \
    tdnf clean all

WORKDIR /src

# Only the sources the C++ build needs, so that editing the web layer does not
# invalidate this stage.
COPY CMakeLists.txt ./
COPY core ./core
COPY cli ./cli
COPY tests ./tests

RUN cmake -S . -B build -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/opt/scitt-sd && \
    cmake --build build --target scitt_sd_tool && \
    cmake --install build --component tool 2>/dev/null || \
    (mkdir -p /opt/scitt-sd/bin && cp build/scitt-sd /opt/scitt-sd/bin/scitt-sd)

# Collect only the OpenSSL shared libraries the tool needs. glibc, libstdc++,
# and the dynamic loader must come from the host/runtime distribution; copying
# Azure Linux versions beside the binary makes an extracted tool crash on an
# Ubuntu GitHub runner.
RUN mkdir -p /opt/scitt-sd/lib && \
    ldd /opt/scitt-sd/bin/scitt-sd > /tmp/scitt-sd-ldd && \
    ! grep -q 'not found' /tmp/scitt-sd-ldd && \
    awk '$1 ~ /^lib(crypto|ssl)\.so/ && $3 ~ /^\// {print $3}' \
      /tmp/scitt-sd-ldd > /tmp/scitt-sd-libs && \
    while IFS= read -r library; do cp -L "${library}" /opt/scitt-sd/lib/; done \
      < /tmp/scitt-sd-libs && \
    /opt/scitt-sd/bin/scitt-sd --version

FROM base

ARG CCF_VERSION

COPY --from=snapshot-extractor /tmp/tdnf_snapshottime /tmp/tdnf_snapshottime

# Runtime dependencies: OpenSSL for the tool, Python for the control plane.
RUN TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime="${TDNF_SNAPSHOTTIME}" \
    ca-certificates \
    curl \
    openssl-libs \
    python3.12 \
    python3-pip \
    shadow-utils \
    tini && \
    tdnf clean all

COPY --from=builder /opt/scitt-sd /opt/scitt-sd

ENV PATH="/opt/scitt-sd/bin:/opt/venv/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/scitt-sd/lib" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SDC_CLI=/opt/scitt-sd/bin/scitt-sd \
    SDC_DATA_DIR=/var/lib/scitt-sd

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

# The control plane never gains a COSE, CBOR or cryptography dependency: it
# only moves opaque bytes between the C++ tool and HTTP. Official receipt
# verification runs in the pinned submodule's own virtual environment, outside
# this image.
RUN python3.12 -m venv /opt/venv && \
    /opt/venv/bin/pip install --disable-pip-version-check --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --disable-pip-version-check --no-cache-dir . && \
    ! /opt/venv/bin/python -c 'import pycose' 2>/dev/null && \
    ! /opt/venv/bin/python -c 'import cbor2' 2>/dev/null && \
    ! /opt/venv/bin/python -c 'import cryptography' 2>/dev/null

RUN groupadd --system scitt && \
    useradd --system --gid scitt --home-dir /app --shell /sbin/nologin scitt && \
    mkdir -p /var/lib/scitt-sd && \
    chown -R scitt:scitt /var/lib/scitt-sd

USER scitt

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD curl --fail --silent http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["/opt/venv/bin/python", "-m", "uvicorn", "--factory", \
    "scitt_selective_disclosure.web.app:create_app", \
    "--host", "0.0.0.0", "--port", "8080"]
