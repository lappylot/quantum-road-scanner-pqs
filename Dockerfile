FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OQS_INSTALL_PATH=/usr/local

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build build-essential pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG LIBOQS_VERSION=0.14.0

RUN git clone --branch "v${LIBOQS_VERSION}" --depth 1 \
      --recurse-submodules https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_USE_OPENSSL=OFF \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -G Ninja \
 && cmake --build /tmp/liboqs/build --parallel \
 && cmake --install /tmp/liboqs/build \
 && rm -rf /tmp/liboqs

RUN printf "/usr/local/lib\n" > /etc/ld.so.conf.d/usr-local-lib.conf && ldconfig
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ----- Pin liboqs-python to v0.12.0 from GitHub -----
RUN pip install --no-cache-dir \
    "git+https://github.com/open-quantum-safe/liboqs-python@v0.12.0"

COPY . .

RUN useradd -ms /bin/bash appuser \
 && mkdir -p /app/static \
 && chmod 755 /app/static \
 && chown -R appuser:appuser /app

USER appuser

EXPOSE 3000

CMD ["gunicorn","main:app","-b","0.0.0.0:3000","-w","4","-k","gthread",
     "--threads","4","--timeout","180","--graceful-timeout","30",
     "--log-level","info","--preload","--max-requests","1000",
     "--max-requests-jitter","200"]
