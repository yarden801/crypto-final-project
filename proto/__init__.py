# proto/__init__.py
import importlib, sys
from pathlib import Path

pkg_dir = Path(__file__).resolve().parent
if str(pkg_dir) not in sys.path:
    sys.path.insert(0, str(pkg_dir))

ca_pb2 = importlib.import_module("proto.ca_pb2")
ca_pb2_grpc = importlib.import_module("proto.ca_pb2_grpc")

__all__ = ["ca_pb2", "ca_pb2_grpc"]

