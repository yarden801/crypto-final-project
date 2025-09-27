FROM python:3.11-slim
WORKDIR /app

# system deps (as before)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential protobuf-compiler && rm -rf /var/lib/apt/lists/*

# copy only requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# now copy code (smaller thanks to .dockerignore)
COPY proto ./proto
COPY common ./common
COPY sharedca ./sharedca    # or ca_node if you didn’t rename
COPY client ./client

# compile protos
RUN python -m grpc_tools.protoc -I./proto --python_out=. --grpc_python_out=. ./proto/ca.proto

CMD ["python","-m","client.client"]
