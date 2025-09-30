import os
import subprocess


def run(cmd):
    print("\n$", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def main():
    num_levels = int(os.getenv("NUM_LEVELS", "2"))
    trust_anchor = os.getenv("TRUST_ANCHOR", "level1_master_pk.hex")

    print("=== 1. Create cert chain ===", flush=True)
    for level in range(1, num_levels + 2):
        cn = "Level1CA" if level == 1 else (
            f"endpoint" if level == num_levels + 1 else f"Level{level}CA"
        )
        ca_flag = ["--ca"] if level < num_levels + 1 else []
        run(["python", "-m", "client.sign", "--level", str(level), "--cn", cn] + ca_flag)

    print("\n=== 2. Initial Validity Checks ===", flush=True)
    for level in range(1, num_levels + 2):
        cn = "Level1CA" if level == 1 else (
            f"endpoint" if level == num_levels + 1 else f"Level{level}CA"
        )
        run([
            "python", "-m", "client.is_valid",
            f"certs/level{level}_{cn}.pem",
            "--trust-anchor", trust_anchor
        ])

    if num_levels >= 2:
        print("\n=== 3. Revoke INTER ===", flush=True)
        run(["python", "-m", "client.revoke", "--revoke", "certs/level2_Level2CA.pem"])

    print("\n=== 4. Validity After Revocation ===", flush=True)
    for level in range(1, num_levels + 2):
        cn = "Level1CA" if level == 1 else (
            f"endpoint" if level == num_levels + 1 else f"Level{level}CA"
        )
        run([
            "python", "-m", "client.is_valid",
            f"certs/level{level}_{cn}.pem",
            "--trust-anchor", trust_anchor
        ])


if __name__ == "__main__":
    main()
