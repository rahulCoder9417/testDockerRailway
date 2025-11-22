# =====================================================================
# 1. Base Image (Ubuntu 22.04) – good for all languages + node-pty
# =====================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

# =====================================================================
# 2. Install Core Tools
# =====================================================================
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    nano \
    build-essential \
    software-properties-common \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# =====================================================================
# 3. Install Node.js (LTS v20)
# =====================================================================
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get update \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# =====================================================================
# 4. Install Python3 + pip
# =====================================================================
RUN apt-get update && apt-get install -y python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# =====================================================================
# 5. Install OpenJDK 17 (Java)
# =====================================================================
RUN apt-get update && apt-get install -y openjdk-17-jdk \
    && rm -rf /var/lib/apt/lists/*

# =====================================================================
# 6. Install Go 1.22
# =====================================================================
RUN wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin"

# =====================================================================
# 7. Install PHP
# =====================================================================
RUN apt-get update && apt-get install -y \
    php \
    php-cli \
    php-mbstring \
    php-xml \
    php-curl \
    && rm -rf /var/lib/apt/lists/*

# =====================================================================
# 8. Install Rust (Rustup)
# =====================================================================
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# =====================================================================
# 9. Install .NET SDK 7
# =====================================================================
RUN wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O /tmp/msprod.deb \
    && dpkg -i /tmp/msprod.deb \
    && apt-get update \
    && apt-get install -y dotnet-sdk-7.0 \
    && rm /tmp/msprod.deb \
    && rm -rf /var/lib/apt/lists/*

# =====================================================================
# 10. Install gcc/g++
# =====================================================================
RUN apt-get update && apt-get install -y gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# =====================================================================
# 11. Optional global npm tools
# =====================================================================
RUN npm install -g yarn pnpm typescript

# =====================================================================
# 12. Setup App
# =====================================================================
WORKDIR /usr/src/app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

# =====================================================================
# 13. Expose Render Port
# =====================================================================
EXPOSE 3000

CMD ["npm", "start"]
