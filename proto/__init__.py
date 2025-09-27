import importlib, sys
from pathlib import Path

pkg_dir = Path(__file__).resolve().parent
if str(pkg_dir) not in sys.path:
    sys.path.insert(0, str(pkg_dir))

mixnet_pb2 = importlib.import_module("mixnet_pb2")
mixnet_pb2_grpc = importlib.import_module("mixnet_pb2_grpc")
__all__ = ["mixnet_pb2", "mixnet_pb2_grpc"]
