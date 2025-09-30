# Threshold Certificate Authority System

## Introduction

This project implements a distributed Threshold Certificate Authority (TCA) system that enables the issuance of digital certificates in a manner independent of any single entity. It incorporates distributed trust and fault tolerance through threshold cryptographic signatures, specifically using BLS (Boneh-Lynn-Shacham) signatures with Shamir secret sharing.
The system supports two modes of operation:

1. **Flat Mode** – A single distributed CA cluster acts as the trust anchor. All certificates are issued and verified directly against this cluster. This configuration is simpler and suitable for controlled environments or demonstrations.

2. **Hierarchical Mode** – The system can also run as a regular PKI hierarchy, where each layer (Root, Intermediate, Leaf) is implemented as a distributed CA cluster. Every layer enforces threshold signing and revocation, closely mirroring the real-world internet trust model while retaining the benefits of decentralization.

The system is designed for environments requiring robust security where no single point of failure can compromise certificate authority operations. Clients submit certificate signing requests (CSR equivalent) to multiple CA nodes, which collectively generate threshold signatures that require only a quorum (threshold) of nodes to participate, providing fault tolerance against unresponsive or malicious nodes.

Key features:
- **Threshold BLS Signatures**: Distributed private key using Shamir secret sharing
- **gRPC-based Communication**: Efficient distributed communication protocol
- **Fault Tolerance**: Continues operation with threshold out of n nodes
- **Threshold Revocation** Certificates can be revoked through distributed consensus and persisted throgh local CRL
- **Dockerized Deployment** Easy setup and orchestration of multiple CA nodes and levels using Docker and dynamic Compose generation.
d
## Components

### Architecture Overview
The system consists of four main components:
1. **CA Nodes**: Distributed certificate authority servers holding partial keys
2. **Client**: Certificate requester that orchestrates threshold signing and verification
3. **Common Libraries**: Shared cryptographic utilities and certificate handling
4. **gRPC Protocol**: Defines communication interfaces between components

### CA Nodes (`sharedca/`)
Each CA node (`server.py`) holds a portion of the threshold private key and can generate partial BLS signatures:
- **Key Generation**: Uses Shamir secret sharing to distribute master private key shares
- **Partial Signing**: Creates BLS partial signatures on certificate TBS (To-Be-Signed) data
- **Revocation**: Threashold revocation; Maintains in-memory CRL; revokes are roadcast to all nodes; includes OCSP capability
- **Configuration**: Node ID, total nodes, threshold via environment variables

### Client (`client/`)
The client application (`client.py`) handles certificate issuance workflow:
- **Key Pair Generation**: Creates RSA keypair for certificate subject
- **CSR Creation**: Builds TBS certificate structure locally
- **Threshold Collection**: Requests partial signatures from CA nodes until threshold met
- **Signature Aggregation**: Combines partial signatures using Lagrange interpolation
- **Verification**: Validates final certificate using master public key

### Common Libraries (`common/`)
Shared cryptographic and certificate utilities:
- **`util.py`**: RSA keypair generation and basic crypto operations
- **`cert.py`**: Certificate class with PEM encoding/decoding and TBS serialization

### Protocol Definitions (`proto/`)
gRPC service definitions:
- **`ca.proto`**: Defines CA node services (SignPartial, Revoke, CRL, OCSP)
- Generated Python files (`*_pb2.py`, `*_pb2_grpc.py`) from protobuf

### Configuration and Infrastructure
- **`requirements.txt`**: Python package dependencies (blspy, protobuf, grpcio and grpcio-tools, pycryptodome, py-ecc)
- **`generate_compose.py`**: A script that can generate a docker compose file with configurable number of nodes, threshold etc.
- **`setup.py`**: python script that sets up the system, including secret sharing and usage of the above docker compose generation. 

## How to Run

### Prerequisites
- Docker and Docker Compose installed
- Python 3.9+ (for usage of setup.py file and if running locally)

### Quick Start with Docker Compose
1. **Clone the repository** (if not already done)
2. **Setup the system**: run setup.py
 ```bash 
 python setup.py --num-levels 3 --nodes-per-level 3 --threshold 2
 ```
**Note:** For flat mode, set --num-levels 2.
  - Level 1 = Root CA (distributed cluster)
  - Level 2 = Endpoint (leaf certificate)
    For a hierarchical deployment, use >=2
  
This will create docker-compose.yml and node config files. If you already have them from previous runs, skip to 3.
3.. **Start the distributed CA system**:
   ```bash
   docker-compose up --build
   ```
   This launches the current docker compose file with required number of levels, nodes and threshold.
   
3. **Monitor output**: Each client will output the generated certificate upon successful threshold signing.
4. **Stop the system**:
   ```bash
   docker-compose down
   ```

### Configuration Changes
You can manually modify system parameters in `docker-compose.yml`.
This can also be done automatically in `generate_compose.py` and in `setup.py`. 
You cannot manually (or with generate_compose) increase number of nodes without using `setup.py`, as this will mean that you don't create node config for them. 
But you can manually delete nodes. If you delete too many nodes, you may never reach threshold.

## Example Usage TODO change 

When running, a successful certificate issuance will output:

```
=== Threshold Cert (client-aggregated) ===
-----BEGIN CERTIFICATE-----
...
Subject: CN=test-client
Issuer: CN=ThreshRoot
...
-----END CERTIFICATE-----

verify: True
```

This indicates:
- Certificate was successfully signed with threshold BLS signature
- Aggregation collected at least 2 partial signatures
- Cryptographic verification passed using master public key

## Limitations and Development Notes

- **Demo Implementation**: Uses fixed seed for reproducible key generation (not production-ready)
- **Basic Fault Tolerance**: No advanced recovery mechanisms for persistent node failures

The current implementation demonstrates the core threshold signing concept. Production deployment would require secure key generation, distributed storage, synchronization protocols, and comprehensive testing scenarios.

## File Structure
```
├── client/          # Client application
├── sharedca/        # CA node implementations
├── common/          # Shared utilities
├── proto/           # gRPC protocol definitions
├── docker-compose.yml       # Container orchestration
├── Dockerfile               # Container configuration
├── setup.py                 # System configuration and secret sharing
├── generate_compose.py      # Creates docker compose file 
└── requirements.txt    # Python dependencies
