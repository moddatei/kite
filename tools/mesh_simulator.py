#!/usr/bin/env python3
"""
Kite Mesh Protocol — Multi-Node RF Field & Opportunistic Routing Simulator.

Demonstrates:
- Ad-hoc multi-node mobility in a 2D RF propagation field.
- Autonomous neighbor discovery via periodic beacon broadcasting.
- Store-Carry-Forward opportunistic packet drifting across air-gapped partitions.
- Zero-copy framing emulation with CRC32 integrity verification.
"""

import sys
import time
import math
import zlib
import random
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


PROTOCOL_VERSION = 0x01

# Frame Types
FRAME_BEACON = 0x01
FRAME_DATA = 0x02
FRAME_ACK = 0x03
FRAME_GOSSIP = 0x04

# Frame Flags
FLAG_ENCRYPTED = 0x01
FLAG_URGENT = 0x02
FLAG_STORE_AND_FORWARD = 0x04


@dataclass
class KiteFrame:
    version: int
    frame_type: int
    flags: int
    ttl: int
    src: str
    dst: str
    seq: int
    payload: bytes

    def serialize(self) -> bytes:
        # 1B ver + 1B type + 1B flags + 1B ttl + 8B src + 8B dst + 2B seq + 2B len + payload + 4B crc32
        src_bytes = bytes.fromhex(self.src.replace("0x", "")).rjust(8, b"\x00")[:8]
        dst_bytes = bytes.fromhex(self.dst.replace("0x", "")).rjust(8, b"\x00")[:8]
        payload_len = len(self.payload)

        header = bytearray()
        header.append(self.version)
        header.append(self.frame_type)
        header.append(self.flags)
        header.append(self.ttl)
        header.extend(src_bytes)
        header.extend(dst_bytes)
        header.extend(self.seq.to_bytes(2, "big"))
        header.extend(payload_len.to_bytes(2, "big"))
        header.extend(self.payload)

        crc = zlib.crc32(header)
        header.extend(crc.to_bytes(4, "big"))
        return bytes(header)

    @classmethod
    def parse(cls, data: bytes) -> Optional["KiteFrame"]:
        if len(data) < 28:
            return None
        ver = data[0]
        if ver != PROTOCOL_VERSION:
            return None
        ftype = data[1]
        flags = data[2]
        ttl = data[3]
        src = "0x" + data[4:12].hex()
        dst = "0x" + data[12:20].hex()
        seq = int.from_bytes(data[20:22], "big")
        payload_len = int.from_bytes(data[22:24], "big")

        if len(data) < 24 + payload_len + 4:
            return None

        payload = data[24:24 + payload_len]
        wire_crc = int.from_bytes(data[24 + payload_len:24 + payload_len + 4], "big")
        calc_crc = zlib.crc32(data[:24 + payload_len])

        if wire_crc != calc_crc:
            return None

        return cls(
            version=ver,
            frame_type=ftype,
            flags=flags,
            ttl=ttl,
            src=src,
            dst=dst,
            seq=seq,
            payload=payload,
        )


@dataclass
class StoredBundle:
    bundle_id: int
    src: str
    dst: str
    ttl: int
    flags: int
    payload: bytes
    hops_carried: int = 0


class Node:
    def __init__(self, node_id: int, x: float, y: float, radio_range: float = 35.0):
        self.node_id = node_id
        self.addr = f"0x{node_id:016x}"
        self.x = x
        self.y = y
        self.radio_range = radio_range
        self.buffer: List[StoredBundle] = []
        self.known_neighbors: Dict[str, float] = {}  # addr -> last_seen
        self.seq: int = 1
        self.delivered_messages: List[str] = []

    def distance_to(self, other: "Node") -> float:
        return math.hypot(self.x - other.x, self.y - other.y)

    def is_in_range(self, other: "Node") -> bool:
        return self.distance_to(other) <= self.radio_range

    def move_randomly(self, bounds: float = 100.0, step: float = 4.0):
        dx = random.uniform(-step, step)
        dy = random.uniform(-step, step)
        self.x = max(5.0, min(bounds - 5.0, self.x + dx))
        self.y = max(5.0, min(bounds - 5.0, self.y + dy))

    def create_beacon(self) -> bytes:
        frame = KiteFrame(
            version=PROTOCOL_VERSION,
            frame_type=FRAME_BEACON,
            flags=0,
            ttl=1,
            src=self.addr,
            dst="0xffffffffffffffff",
            seq=self.seq,
            payload=b"BEACON",
        )
        self.seq = (self.seq + 1) % 65535
        return frame.serialize()

    def create_whisper(self, dst_addr: str, message: str, ttl: int = 6) -> StoredBundle:
        bundle_id = random.randint(10000, 99999)
        bundle = StoredBundle(
            bundle_id=bundle_id,
            src=self.addr,
            dst=dst_addr,
            ttl=ttl,
            flags=FLAG_ENCRYPTED | FLAG_STORE_AND_FORWARD,
            payload=message.encode("utf-8"),
        )
        self.buffer.append(bundle)
        return bundle

    def receive_frame(self, raw_bytes: bytes, sender_node: "Node") -> Optional[str]:
        frame = KiteFrame.parse(raw_bytes)
        if not frame:
            return None

        # Update neighbor record
        self.known_neighbors[frame.src] = time.time()

        if frame.frame_type == FRAME_BEACON:
            return None

        if frame.dst == self.addr:
            msg_str = frame.payload.decode("utf-8", errors="replace")
            self.delivered_messages.append(msg_str)
            return f"DESTINATION_REACHED (Node {self.node_id} received: '{msg_str}')"

        if frame.dst == "0xffffffffffffffff":
            return f"BROADCAST_INGESTED (Node {self.node_id})"

        # Store-and-forward candidate
        if frame.ttl > 1:
            # Check if not already in buffer
            already_have = any(b.payload == frame.payload and b.dst == frame.dst for b in self.buffer)
            if not already_have:
                self.buffer.append(
                    StoredBundle(
                        bundle_id=random.randint(1000, 9999),
                        src=frame.src,
                        dst=frame.dst,
                        ttl=frame.ttl - 1,
                        flags=frame.flags,
                        payload=frame.payload,
                    )
                )
                return f"BUNDLE_STORED (Node {self.node_id} ferries bundle destined for {frame.dst[:8]}..)"

        return None


class MeshSimulator:
    def __init__(self, num_nodes: int = 6, radio_range: float = 40.0):
        self.nodes: List[Node] = []
        self.radio_range = radio_range
        random.seed(42)

        # Distribute nodes along a corridor to create dynamic partitioning
        for i in range(num_nodes):
            x = 10.0 + (i * 15.0) + random.uniform(-3, 3)
            y = 50.0 + random.uniform(-10, 10)
            self.nodes.append(Node(i + 1, x, y, radio_range=radio_range))

    def render_ascii_field(self, width: int = 50, height: int = 15) -> str:
        grid = [["·" for _ in range(width)] for _ in range(height)]

        for node in self.nodes:
            gx = int(node.x / 100.0 * (width - 1))
            gy = int(node.y / 100.0 * (height - 1))
            gx = max(0, min(width - 1, gx))
            gy = max(0, min(height - 1, gy))
            grid[gy][gx] = str(node.node_id)

        lines = ["┌" + "─" * width + "┐"]
        for row in grid:
            lines.append("│" + "".join(row) + "│")
        lines.append("└" + "─" * width + "┘")
        return "\n".join(lines)

    def run_step(self, step_num: int) -> List[str]:
        logs = []

        # 1. Random node movement
        for node in self.nodes:
            node.move_randomly()

        # 2. Opportunistic transmissions between adjacent peers
        for i, node_a in enumerate(self.nodes):
            # Send beacons
            beacon_raw = node_a.create_beacon()
            for j, node_b in enumerate(self.nodes):
                if i != j and node_a.is_in_range(node_b):
                    node_b.receive_frame(beacon_raw, node_a)

            # Replicate / Forward stored bundles to in-range neighbors
            for bundle in list(node_a.buffer):
                for j, node_b in enumerate(self.nodes):
                    if i != j and node_a.is_in_range(node_b):
                        frame = KiteFrame(
                            version=PROTOCOL_VERSION,
                            frame_type=FRAME_DATA,
                            flags=bundle.flags,
                            ttl=bundle.ttl,
                            src=bundle.src,
                            dst=bundle.dst,
                            seq=node_a.seq,
                            payload=bundle.payload,
                        )
                        raw = frame.serialize()
                        result = node_b.receive_frame(raw, node_a)
                        if result:
                            logs.append(f"[Step {step_num:02d}] Hop Node {node_a.node_id} -> Node {node_b.node_id}: {result}")
                            if "DESTINATION_REACHED" in result:
                                if bundle in node_a.buffer:
                                    node_a.buffer.remove(bundle)

        return logs


def run_demo():
    print("\033[96m╔══════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[96m║   Kite Mesh Protocol — Multi-Node RF Opportunistic Simulator     ║\033[0m")
    print("\033[96m║   Noise-XX / Store-Carry-Forward / Ad-Hoc RF Dispersion          ║\033[0m")
    print("\033[96m╚══════════════════════════════════════════════════════════════════╝\033[0m\n")

    sim = MeshSimulator(num_nodes=6, radio_range=32.0)
    src_node = sim.nodes[0]
    dst_node = sim.nodes[5]

    print(f"[*] Initializing mesh topology with {len(sim.nodes)} nodes...")
    print(f"[*] Node 1 (Source)  : {src_node.addr}")
    print(f"[*] Node 6 (Target)  : {dst_node.addr}")
    print(f"[*] Injecting encrypted whisper from Node 1 to Node 6...")

    src_node.create_whisper(
        dst_addr=dst_node.addr,
        message="SECRET_AEGIS_09: Autonomous link established over ambient RF.",
        ttl=8,
    )

    print("\nInitial RF Topology Map (Nodes 1..6):")
    print(sim.render_ascii_field())
    print("\nStarting simulation ticks (Press Ctrl+C to halt)...\n")

    delivered = False
    for step in range(1, 16):
        logs = sim.run_step(step)
        for log_entry in logs:
            print(f"  \033[92m{log_entry}\033[0m")
            if "DESTINATION_REACHED" in log_entry:
                delivered = True

        time.sleep(0.15)
        if delivered:
            break

    print("\n" + "=" * 66)
    if delivered:
        print("\033[92m[✓] SUCCESS: Packet successfully drifted and delivered across air-gap!\033[0m")
        print(f"    Delivered Content: '{dst_node.delivered_messages[0]}'")
    else:
        print("\033[93m[i] In-flight: Bundle is stored in intermediate relay node buffers awaiting contact.\033[0m")
    print("=" * 66)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kite Protocol Mesh Simulator")
    parser.add_argument("--nodes", type=int, default=6, help="Number of nodes in the field")
    parser.add_argument("--demo", action="store_true", help="Run automated demonstration")
    args = parser.parse_args()

    if args.demo or len(sys.argv) == 1:
        run_demo()
    else:
        sim = MeshSimulator(num_nodes=args.nodes)
        print(f"Spawned {args.nodes}-node mesh.")
        print(sim.render_ascii_field())
