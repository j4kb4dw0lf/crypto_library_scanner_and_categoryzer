FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

ENV GIT_TERMINAL_PROMPT=0

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    clang-14 \
    libclang-14-dev \
    ca-certificates \
    sqlite \
    && ln -s /usr/lib/llvm-14/lib/libclang.so.1 /usr/lib/libclang.so \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib/libclang.so.1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY ./scanner ./scanner
COPY ./scripts ./scripts

ENTRYPOINT ["python", "-m", "scanner.main"]
