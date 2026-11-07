FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends git cmake build-essential ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch b12110 https://github.com/ggml-org/llama.cpp.git /llama
RUN cmake -S /llama -B /llama/build -DGGML_NATIVE=OFF -DGGML_OPENMP=OFF -DLLAMA_CURL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_SERVER=ON && cmake --build /llama/build --target llama-server -j2
FROM python:3.13-slim-bookworm
WORKDIR /app
COPY --from=build /llama/build/bin/ /app/runtime/
COPY app.py local_runtime.py index.html MODEL_MANIFEST.json /app/
RUN mkdir -p /app/data /app/models
ENV BIND_HOST=0.0.0.0
EXPOSE 8000
CMD ["python", "app.py"]
