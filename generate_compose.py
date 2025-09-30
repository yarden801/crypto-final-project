#!/usr/bin/env python3
"""
Generator for configurable docker-compose.yml for distributed CA system
with arbitrary levels (root, intermediates, etc.).

Usage:
    python generate_compose.py [--num-levels L] [--nodes-per-level N] [--threshold T] [--output FILE]

Environment variables (override command line args):
    NUM_LEVELS: Number of levels (default: 2)
    NODES_PER_LEVEL: Nodes per level (default: 3)
    THRESHOLD: Signature threshold (default: 2)
"""

import argparse
import os
import sys

def generate_compose(num_levels, nodes_per_level, threshold):
    lines = []
    lines.append('version: "3.9"')
    lines.append('')
    lines.append('services:')

    # Generate services per level
    base_ports = {1: 50060, 2: 50070, 3: 50080}  # adjust if >3 levels
    for level in range(1, num_levels + 1):
        for i in range(1, nodes_per_level + 1):
            port = base_ports.get(level, 50060 + 10*level) + i
            name = f"level{level}_node{i}"
            lines.append(f'  {name}:')
            lines.append('    build: .')
            lines.append(f'    container_name: {name}')
            lines.append('    command: ["python", "-m", "sharedca.server"]')
            lines.append('    environment:')
            lines.append(f'      - CONFIG_PATH=node_config/level{level}/node{i}.json')
            lines.append(f'      - GRPC_PORT={port}')
            lines.append('    volumes:')
            lines.append('      - .:/app')
            lines.append('    ports:')
            lines.append(f'      - "{port}:{port}"')
            lines.append('')

    # Generate client
    lines.append('  client:')
    lines.append('    build: .')
    lines.append('    container_name: client')
    lines.append('    command: ["python", "-m", "client.demo"]')
    lines.append('    environment:')
    lines.append(f'      - NUM_LEVELS={num_levels}')
    lines.append(f'      - TRUST_ANCHOR=level1_master_pk.hex')    

    for level in range(1, num_levels + 1):
        base = base_ports.get(level, 50060 + 10*level)
        addrs = ",".join([f"level{level}_node{i}:{base+i}" for i in range(1, nodes_per_level+1)])
        lines.append(f'      - LEVEL{level}_NODES={addrs}')

    lines.append(f'      - THRESHOLD={threshold}')
    lines.append('    volumes:')
    lines.append('      - .:/app')
    lines.append('    depends_on:')
    for level in range(1, num_levels + 1):
        for i in range(1, nodes_per_level + 1):
            lines.append(f'      - level{level}_node{i}')
    lines.append('')

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description='Generate docker-compose.yml for distributed CA system')
    parser.add_argument(
        '--num-levels', type=int,
        default=int(os.environ.get('NUM_LEVELS', 2)),
        help='Number of levels (default: 2 or NUM_LEVELS env var)'
    )
    parser.add_argument(
        '--nodes-per-level', type=int,
        default=int(os.environ.get('NODES_PER_LEVEL', 3)),
        help='Nodes per level (default: 3 or NODES_PER_LEVEL env var)'
    )
    parser.add_argument(
        '--threshold', type=int,
        default=int(os.environ.get('THRESHOLD', 2)),
        help='Signature threshold (default: 2 or THRESHOLD env var)'
    )
    parser.add_argument(
        '--output', '-o', type=argparse.FileType('w'),
        default=sys.stdout,
        help='Output file (default: stdout)'
    )

    args = parser.parse_args()
    compose_content = generate_compose(args.num_levels, args.nodes_per_level, args.threshold)
    args.output.write(compose_content + "\n")

    if args.output != sys.stdout:
        print(f"Generated docker-compose.yml with {args.num_levels} levels, {args.nodes_per_level} nodes/level, threshold {args.threshold}")

if __name__ == '__main__':
    main()
