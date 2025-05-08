from infisical_sdk import InfisicalSDKClient
import time
import os
import random
import string


def loadEnvVarsFromFileIntoEnv():
    d = dict()
    with open("./.env", "r") as fp:
        for line in fp:
            line = line.strip()
            if line and not line.startswith("#"):
                line = line.split("=", 1)
                d[line[0]] = line[1]

    for key, value in d.items():
        os.environ[key] = value


loadEnvVarsFromFileIntoEnv()

SECRETS_PROJECT_ID = os.getenv("SECRETS_PROJECT_ID")
SECRETS_ENVIRONMENT_SLUG = os.getenv("SECRETS_ENVIRONMENT_SLUG")

MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_ID = os.getenv(
    "MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_ID"
)
MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_SECRET = os.getenv(
    "MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_SECRET"
)
SITE_URL = os.getenv("SITE_URL")

cache_enabled_client = InfisicalSDKClient(host=SITE_URL, cache_ttl=10)
cache_enabled_client.auth.universal_auth.login(
    MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_ID,
    MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_SECRET,
)


time_start_cache_disabled = time.time()


def randomStringNoSpecialChars(length: int = 10) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


created_sec = cache_enabled_client.secrets.create_secret_by_name(
    secret_name=f"TEST_{randomStringNoSpecialChars()}",
    project_id=SECRETS_PROJECT_ID,
    environment_slug=SECRETS_ENVIRONMENT_SLUG,
    secret_path="/",
    secret_value=f"secret_value_{randomStringNoSpecialChars()}",
)


single_secret_cached = cache_enabled_client.secrets.get_secret_by_name(
    secret_name=created_sec.secretKey,
    project_id=SECRETS_PROJECT_ID,
    environment_slug=SECRETS_ENVIRONMENT_SLUG,
    secret_path="/",
    expand_secret_references=True,
    include_imports=True,
)

print(single_secret_cached)


deleted_secret = cache_enabled_client.secrets.delete_secret_by_name(
    secret_name=created_sec.secretKey,
    project_id=SECRETS_PROJECT_ID,
    environment_slug=SECRETS_ENVIRONMENT_SLUG,
    secret_path="/",
)

print(deleted_secret)

# Should error
try:
    single_secret_cached = cache_enabled_client.secrets.get_secret_by_name(
        secret_name=created_sec.secretKey,
        project_id=SECRETS_PROJECT_ID,
        environment_slug=SECRETS_ENVIRONMENT_SLUG,
        secret_path="/",
        expand_secret_references=True,
        include_imports=True,
    )
except Exception as e:
    print(e)
    print("Good, we errored as expected!")
