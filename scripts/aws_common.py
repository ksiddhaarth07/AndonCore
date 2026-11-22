import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except ImportError:
    pass


def env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise SystemExit(f"Missing required setting {name}. Copy .env.example to .env and set it.")
    return value


def aws_session():
    import boto3
    profile = env("AWS_PROFILE", "")
    region = env("AWS_REGION", "us-east-1")
    return boto3.Session(profile_name=profile or None, region_name=region)


def write_env_updates(updates):
    path = Path(__file__).resolve().parents[1] / ".env"
    current = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                current[key] = value
    current.update({k: str(v) for k, v in updates.items() if v is not None})
    path.write_text("\n".join(f"{k}={v}" for k, v in current.items()) + "\n", encoding="utf-8")

