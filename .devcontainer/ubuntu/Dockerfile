# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:24.04

ARG USERNAME=mido
ARG USER_UID=1000
ARG USER_GID=$USER_UID

ARG NODE_MAJOR=20
ARG LLVM_VERSION=18

ENV DEBIAN_FRONTEND=noninteractive


RUN apt-get update && apt-get install -y --no-install-recommends \
    black \
    ca-certificates \
    curl \
    fakeroot \
    flake8 \
    gcc \
    git \
    gpg \
    make \
    patchelf \
    pycodestyle \
    python3-pip \
    python3-bashate \
    python3-dev \
    python3-build \
    python3-all-dev \
    # python3-stdeb \
    python3-venv \
    ssh \
    bear \
    build-essential \
    cmake \
    cppcheck \
    python3-kconfiglib \
    kconfig-frontends-nox \
    unzip \
    xxd \
    doxygen \
    sphinx \
    hitch \
    lcov \
    libcmocka-dev \
    net-tools \
    jq \
    valgrind \
    debhelper \
    swig \
    dh-python \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    && apt-get clean -y\
    && update-alternatives --install /usr/bin/python python /usr/bin/python3 50

# Remove this once stdeb is fully released for ubuntu:24.04 (python3.12)
RUN pip3 install \
    auditwheel==6.3.0 \
    git+https://github.com/astraw/stdeb.git \
    --break-system-packages

RUN echo "deb https://apt.llvm.org/noble/ llvm-toolchain-noble-${LLVM_VERSION} main" > /etc/apt/sources.list.d/apt.llvm.org.list && \
    curl -sL https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    apt-get update && apt-get install -y --no-install-recommends \
    clang-format-${LLVM_VERSION} \
    clang-${LLVM_VERSION} \
    lld-${LLVM_VERSION} \
    clang-tidy-${LLVM_VERSION} \
    clang-tools-${LLVM_VERSION} \
    llvm-${LLVM_VERSION}-dev \
    lld-${LLVM_VERSION} \
    llvm-${LLVM_VERSION}-tools \
    libc++-${LLVM_VERSION}-dev \
    libc++abi-${LLVM_VERSION}-dev \
    libclang-common-${LLVM_VERSION}-dev \
    libclang-${LLVM_VERSION}-dev \
    libclang-cpp${LLVM_VERSION}-dev \
    libunwind-${LLVM_VERSION}-dev \
    libclang-rt-${LLVM_VERSION}-dev \
    libpolly-${LLVM_VERSION}-dev \
    && apt-get clean -y \
    && update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/clang-cl clang-cl /usr/bin/clang-cl-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/clang-cpp clang-cpp /usr/bin/clang-cpp-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/clang-check clang-check /usr/bin/clang-check-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/ld.lld-${LLVM_VERSION} 50 \
    && update-alternatives --install /usr/bin/wasm-ld wasm-ld /usr/bin/wasm-ld-${LLVM_VERSION} 50

ENV WASI_PREFIX=/usr/bin/
ARG WASI_SDK_VERSION=24
ENV WASI_SYSROOT=/opt/wasi-sysroot-${WASI_SDK_VERSION}.0

# The builtins file has to be in a specific directory /usr/lib/llvm-${LLVM_VERSION}/lib/clang/${LLVM_VERSION}/lib/wasi/
# Please check https://github.com/WebAssembly/wasi-sdk/releases
RUN curl -fsSL https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION}/wasi-sysroot-${WASI_SDK_VERSION}.0.tar.gz | \
    tar xzC /opt \
    && mkdir /usr/lib/llvm-${LLVM_VERSION}/lib/clang/${LLVM_VERSION}/lib/wasi/ \
    && curl -fsSL https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION}/libclang_rt.builtins-wasm32-wasi-${WASI_SDK_VERSION}.0.tar.gz | \
    tar xzC /usr/lib/llvm-${LLVM_VERSION}/lib/clang/${LLVM_VERSION}/lib/wasi/ --strip-components=1

# Accomodate the user for devcontainer
RUN (userdel -r $USERNAME ; userdel -r `id -nu $USER_UID` ; groupdel `id -gu $USER_GID`) || true \
    && groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME
