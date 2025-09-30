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
- **`revoke.py`**: threshold revocation
- **`is_valid.py`**: chain of certificatiobns validation
- **`sign.py`**: orchestrates issuance
- **`demo.py`**: convenience script that runs an end-to-end demo

### Common Libraries (`common/`)
Shared cryptographic and certificate utilities:
- **`util.py`**: RSA keypair generation and basic crypto operations
- **`cert.py`**: Certificate class with PEM encoding/decoding and TBS serialization

### Protocol Definitions (`proto/`)
gRPC service definitions:
- **`ca.proto`**: Defines CA node services (SignPartial, Revoke, CRL, OCSP)
- Generated Python files (`*_pb2.py`, `*_pb2_grpc.py`) from protobuf

### Configuration and Infrastructure
- **`docker-compose.yml`**: Defines 3 CA nodes and 2 client containers in isolated network
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
 python setup.py --num-levels 2 --nodes-per-level 3 --threshold 2
 ```
**Note:** For flat mode, set --num-levels 1.
    
This will create docker-compose.yml and node config files. If you already have them from previous runs, skip to 3.
3.. **Start the distributed CA system**:
   ```bash
   docker-compose up --build
   ```
   This launches the current docker compose file with required number of levels, nodes and threshold.

4. **run commands on client**:
   You can either run the automated demo or perform the steps manually.
   #### Option A – Run a basic demo
   ```bash
   docker exec client python client/demo.py

   This will:
   1. Create a certificate chain (Root → Intermediate → Endpoint)
   2. Validate the chain
   3. Revoke the intermediate certificate at level 2
   4. Show that the endpoint becomes invalid after revocation

  #### Option B – Run manually
   1. **Create certificate**
      ```bash
      # CA
      docker exec client python -m client.sign --level 1 --cn Level1CA --ca
   
      # Endpoint / leaf certificate
      docker exec client python -m client.sign --level 2 --cn endpoint
   
   2. **Validate certificate**
     ```bash

     docker exec client python -m client.is_valid certs/level1_Level1CA.pem \
         --trust-anchor level1_master_pk.hex
      ```
      
   3. **Revoke**
     ```bash

     docker exec client python -m client.revoke --revoke certs/Level1CA.pem
     ```

   4. **Stop the system**:
      ```bash
      docker-compose down
      ```

### Configuration Changes
You can manually modify system parameters in `docker-compose.yml`.
This can also be done automatically in `generate_compose.py` and in `setup.py`. 
You cannot manually (or with generate_compose) increase number of nodes without using `setup.py`, as this will mean that you don't create node config for them. 
But you can manually delete nodes. If you delete too many nodes, you may never reach threshold.


## Example Usage

Running the demo produces the following sequence:
```
=== 1. Create cert chain ===

$ python -m client.sign --level 1 --cn Level1CA --ca
=== Threshold Cert (aggregated) ===
... Level1CA certificate saved to certs/level1_Level1CA.pem

$ python -m client.sign --level 2 --cn Level2CA --ca
=== Threshold Cert (aggregated) ===
... Level2CA certificate saved to certs/level2_Level2CA.pem
verify against issuer: True

$ python -m client.sign --level 3 --cn endpoint
=== Threshold Cert (aggregated) ===
... endpoint certificate saved to certs/level3_endpoint.pem
verify against issuer: True

=== 2. Initial Validity Checks ===

$ python -m client.is_valid certs/level1_Level1CA.pem --trust-anchor level1_master_pk.hex
Cert is valid

$ python -m client.is_valid certs/level2_Level2CA.pem --trust-anchor level1_master_pk.hex
Cert is valid

$ python -m client.is_valid certs/level3_endpoint.pem --trust-anchor level1_master_pk.hex
Cert is valid

=== 3. Revoke INTER ===

$ python -m client.revoke --revoke certs/level2_Level2CA.pem
Revocation completed, final status: REVOKED (3/3 nodes)

=== 4. Validity After Revocation ===

$ python -m client.is_valid certs/level1_Level1CA.pem --trust-anchor level1_master_pk.hex
Cert is valid

$ python -m client.is_valid certs/level2_Level2CA.pem --trust-anchor level1_master_pk.hex
Cert is INVALID

$ python -m client.is_valid certs/level3_endpoint.pem --trust-anchor level1_master_pk.hex
Cert is INVALID
```

## Limitations and Development Notes
You can read deeper in the Known Issues, Discussion and Future Work section in our document.
In general this is a **Demo Implementation**: Uses fixed seed for reproducible key generation 
- **No Persistance**: Certificates and revocation state lost on restart
- **Basic Fault Tolerance**: No advanced recovery mechanisms for persistent node failures


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
