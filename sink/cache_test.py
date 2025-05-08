from infisical_sdk import InfisicalSDKClient
import time
import os


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

cache_disabled_client = InfisicalSDKClient(host=SITE_URL, cache_ttl=None)
cache_disabled_client.auth.universal_auth.login(
    MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_ID,
    MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_SECRET,
)

cache_enabled_client = InfisicalSDKClient(host=SITE_URL, cache_ttl=10)
cache_enabled_client.auth.universal_auth.login(
    MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_ID,
    MACHINE_IDENTITY_UNIVERSAL_AUTH_CLIENT_SECRET,
)


time_start_cache_disabled = time.time()


for i in range(100):
    all_secrets = cache_disabled_client.secrets.list_secrets(
        project_id=SECRETS_PROJECT_ID,
        environment_slug=SECRETS_ENVIRONMENT_SLUG,
        secret_path="/",
        expand_secret_references=True,
        include_imports=True,
    )

time_end_cache_disabled = time.time()

print(
    f"[CACHE DISABLED] Time taken: {time_end_cache_disabled - time_start_cache_disabled} seconds"
)


time_start_cache_enabled = time.time()

for i in range(100):
    all_secrets = cache_enabled_client.secrets.list_secrets(
        project_id=SECRETS_PROJECT_ID,
        environment_slug=SECRETS_ENVIRONMENT_SLUG,
        secret_path="/",
        expand_secret_references=True,
        include_imports=True,
    )

time_end_cache_enabled = time.time()

print(
    f"[CACHE ENABLED] Time taken: {time_end_cache_enabled - time_start_cache_enabled} seconds"
)


single_secret_cached = cache_enabled_client.secrets.get_secret_by_name(
    secret_name="TEST",
    project_id=SECRETS_PROJECT_ID,
    environment_slug=SECRETS_ENVIRONMENT_SLUG,
    secret_path="/",
    expand_secret_references=True,
    include_imports=True,
)

single_secret_cached = cache_enabled_client.secrets.get_secret_by_name(
    secret_name="TEST",
    project_id=SECRETS_PROJECT_ID,
    environment_slug=SECRETS_ENVIRONMENT_SLUG,
    secret_path="/",
    expand_secret_references=False,
    include_imports=False,
)


single_secret_cached = cache_enabled_client.secrets.get_secret_by_name(
    secret_name="TEST",
    project_id=SECRETS_PROJECT_ID,
    environment_slug=SECRETS_ENVIRONMENT_SLUG,
    secret_path="/",
    expand_secret_references=True,
    include_imports=True,
)
