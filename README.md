# Infisical Python SDK

The Infisical SDK provides a convenient way to interact with the Infisical API.

### Migrating to version 1.0.3 or above

We have recently rolled out our first stable version of the SDK, version `1.0.3` and above.

The 1.0.3 version comes with a few key changes that may change how you're using the SDK.

1. **Removal of `rest`**: The SDK no longer exposes the entire Infisical API. This was nessecary as we have moved away from using an OpenAPI generator approach. We aim to add support for more API resources in the near future. If you have any specific requests, please [open an issue](https://github.com/Infisical/python-sdk-official/issues).

2. **New response types**: The 1.0.3 release uses return types that differ from the older versions. The new return types such as `BaseSecret`, are all exported from the Infisical SDK.

3. **Property renaming**: Some properties on the responses have been slightly renamed. An example of this would be that the `secret_key` property on the `get_secret_by_name()` method, that has been renamed to `secretKey`.

With this in mind, you're ready to upgrade your SDK version to `1.0.3` or above.

You can refer to our [legacy documentation](https://github.com/Infisical/python-sdk-official/tree/9b0403938ee5ae599d42c5f1fdf9158671a15606?tab=readme-ov-file#infisical-python-sdk) if need be.

## Requirements

Python 3.7+

## Installation

```bash
pip install infisicalsdk
```

## Getting Started

```python
from infisical_sdk import InfisicalSDKClient

# Initialize the client
client = InfisicalSDKClient(host="https://app.infisical.com")

# Authenticate (example using Universal Auth)
client.auth.universal_auth.login(
    client_id="<machine-identity-client-id>",
    client_secret="<machine-identity-client-secret>"
)

# Use the SDK to interact with Infisical
secrets = client.secrets.list_secrets(project_id="<project-id>", environment_slug="dev", secret_path="/")
```

## InfisicalSDKClient Parameters

The `InfisicalSDKClient` takes the following parameters, which are used as a global configuration for the lifetime of the SDK instance.

- **host** (`str`, _Optional_): The host URL for your Infisical instance. Defaults to `https://app.infisical.com`.
- **token** (`str`, _Optional_): Specify an authentication token to use for all requests. If provided, you will not need to call any of the `auth` methods. Defaults to `None`
- **cache_ttl** (`int`, _Optional_): The SDK has built-in client-side caching for secrets, greatly improving response times. By default, secrets are cached for 1 minute (60 seconds). You can disable caching by setting `cache_ttl` to `None`, or adjust the duration in seconds as needed.

```python
client = InfisicalSDKClient(
  host="https://app.infisical.com", # Defaults to https://app.infisical.com
  token="<optional-auth-token>", # If not set, use the client.auth() methods.
  cache_ttl = 300 # `None` to disable caching
)
```

## Core Methods

The SDK methods are organized into the following high-level categories:

1. `auth`: Handles authentication methods.
2. `secrets`: Manages CRUD operations for secrets.
3. `kms`: Perform cryptographic operations with Infisical KMS.

### `auth`

The `Auth` component provides methods for authentication:

#### Universal Auth

```python
response = client.auth.universal_auth.login(
    client_id="<machine-identity-client-id>",
    client_secret="<machine-identity-client-secret>"
)
```

#### AWS Auth

```python
response = client.auth.aws_auth.login(identity_id="<machine-identity-id>")
```

### `secrets`

This sub-class handles operations related to secrets:

#### List Secrets

```python
secrets = client.secrets.list_secrets(
    project_id="<project-id>",
    environment_slug="dev",
    secret_path="/",
    expand_secret_references=True, # Optional
    view_secret_value=True, # Optional
    recursive=False, # Optional
    include_imports=True, # Optional
    tag_filters=[] # Optional
)
```

**Parameters:**

- `project_id` (str): The ID of your project.
- `environment_slug` (str): The environment in which to list secrets (e.g., "dev").
- `secret_path` (str): The path to the secrets.
- `expand_secret_references` (bool): Whether to expand secret references.
- `view_secret_value` (bool): Whether or not to include the secret value in the response. If set to false, the `secretValue` will be masked with `<hidden-by-infisical>`. Defaults to true.
- `recursive` (bool): Whether to list secrets recursively.
- `include_imports` (bool): Whether to include imported secrets.
- `tag_filters` (List[str]): Tags to filter secrets.

**Returns:**

- `ListSecretsResponse`: The response containing the list of secrets.

#### Create Secret

```python
new_secret = client.secrets.create_secret_by_name(
    secret_name="NEW_SECRET",
    project_id="<project-id>",
    secret_path="/",
    environment_slug="dev",
    secret_value="secret_value",
    secret_comment="Optional comment",
    skip_multiline_encoding=False,
    secret_reminder_repeat_days=30,  # Optional
    secret_reminder_note="Remember to update this secret"  # Optional
)
```

**Parameters:**

- `secret_name` (str): The name of the secret.
- `project_id` (str): The ID of your project.
- `secret_path` (str): The path to the secret.
- `environment_slug` (str): The environment in which to create the secret.
- `secret_value` (str): The value of the secret.
- `secret_comment` (str, optional): A comment associated with the secret.
- `skip_multiline_encoding` (bool, optional): Whether to skip encoding for multiline secrets.
- `secret_reminder_repeat_days` (Union[float, int], optional): Number of days after which to repeat secret reminders.
- `secret_reminder_note` (str, optional): A note for the secret reminder.

**Returns:**

- `BaseSecret`: The response after creating the secret.

#### Update Secret

```python
updated_secret = client.secrets.update_secret_by_name(
    current_secret_name="EXISTING_SECRET",
    project_id="<project-id>",
    secret_path="/",
    environment_slug="dev",
    secret_value="new_secret_value",
    secret_comment="Updated comment",  # Optional
    skip_multiline_encoding=False,
    secret_reminder_repeat_days=30,  # Optional
    secret_reminder_note="Updated reminder note",  # Optional
    new_secret_name="NEW_NAME"  # Optional
)
```

**Parameters:**

- `current_secret_name` (str): The current name of the secret.
- `project_id` (str): The ID of your project.
- `secret_path` (str): The path to the secret.
- `environment_slug` (str): The environment in which to update the secret.
- `secret_value` (str, optional): The new value of the secret.
- `secret_comment` (str, optional): An updated comment associated with the secret.
- `skip_multiline_encoding` (bool, optional): Whether to skip encoding for multiline secrets.
- `secret_reminder_repeat_days` (Union[float, int], optional): Updated number of days after which to repeat secret reminders.
- `secret_reminder_note` (str, optional): An updated note for the secret reminder.
- `new_secret_name` (str, optional): A new name for the secret.

**Returns:**

- `BaseSecret`: The response after updating the secret.

#### Get Secret by Name

```python
secret = client.secrets.get_secret_by_name(
    secret_name="EXISTING_SECRET",
    project_id="<project-id>",
    environment_slug="dev",
    secret_path="/",
    expand_secret_references=True, # Optional
    view_secret_value=True, # Optional
    include_imports=True, # Optional
    version=None # Optional
)
```

**Parameters:**

- `secret_name` (str): The name of the secret.
- `project_id` (str): The ID of your project.
- `environment_slug` (str): The environment in which to retrieve the secret.
- `secret_path` (str): The path to the secret.
- `expand_secret_references` (bool): Whether to expand secret references.
- `view_secret_value` (bool): Whether or not to include the secret value in the response. If set to false, the `secretValue` will be masked with `<hidden-by-infisical>`. Defaults to true.
- `include_imports` (bool): Whether to include imported secrets.
- `version` (str, optional): The version of the secret to retrieve. Fetches the latest by default.

**Returns:**

- `BaseSecret`: The response containing the secret.

#### Delete Secret by Name

```python
deleted_secret = client.secrets.delete_secret_by_name(
    secret_name="EXISTING_SECRET",
    project_id="<project-id>",
    environment_slug="dev",
    secret_path="/"
)
```

**Parameters:**

- `secret_name` (str): The name of the secret to delete.
- `project_id` (str): The ID of your project.
- `environment_slug` (str): The environment in which to delete the secret.
- `secret_path` (str): The path to the secret.

**Returns:**

- `BaseSecret`: The response after deleting the secret.

### `kms`

This sub-class handles KMS related operations:

#### List KMS Keys

```python
kms_keys = client.kms.list_keys(
    project_id="<project-id>",
    offset=0, # Optional
    limit=100, # Optional
    order_by=KmsKeysOrderBy.NAME, # Optional
    order_direction=OrderDirection.ASC, # Optional
    search=None # Optional
)
```

**Parameters:**

- `project_id` (str): The ID of your project.
- `offset` (int, optional): The offset to paginate from.
- `limit` (int, optional): The page size for paginating.
- `order_by` (KmsKeysOrderBy, optional): The key property to order the list response by.
- `order_direction` (OrderDirection, optional): The direction to order the list response in.
- `search` (str, optional): The text value to filter key names by.

**Returns:**

- `ListKmsKeysResponse`: The response containing the list of KMS keys.

#### Get KMS Key by ID

```python
kms_key = client.kms.get_key_by_id(
    key_id="<key-id>"
)
```

**Parameters:**

- `key_id` (str): The ID of the key to retrieve.

**Returns:**

- `KmsKey`: The specified key.

#### Get KMS Key by Name

```python
kms_key = client.kms.get_key_by_name(
    key_name="my-key",
    project_id="<project-id>"
)
```

**Parameters:**

- `key_name` (str): The name of the key to retrieve.
- `project_id` (str): The ID of your project.

**Returns:**

- `KmsKey`: The specified key.

#### Create KMS Key

```python
kms_key = client.kms.create_key(
    name="my-key",
    project_id="<project-id>",
    encryption_algorithm=SymmetricEncryption.AES_GCM_256,
    description=None # Optional
)
```

**Parameters:**

- `name` (str): The name of the key (must be slug-friendly).
- `project_id` (str): The ID of your project.
- `encryption_algorithm` (SymmetricEncryption): The encryption alogrithm this key should use.
- `description` (str, optional): A description of your key.

**Returns:**

- `KmsKey`: The newly created key.

#### Update KMS Key

```python
updated_key = client.kms.update_key(
    key_id="<key-id>",
    name="my-updated-key", # Optional
    description="Updated description", # Optional
    is_disabled=True # Optional
)
```

**Parameters:**

- `key_id` (str): The ID of the key to be updated.
- `name` (str, optional): The updated name of the key (must be slug-friendly).
- `description` (str): The updated description of the key.
- `is_disabled` (str): The flag to disable operations with this key.

**Returns:**

- `KmsKey`: The updated key.

#### Delete KMS Key

```python
deleted_key = client.kms.delete_key(
    key_id="<key-id>"
)
```

**Parameters:**

- `key_id` (str): The ID of the key to be deleted.

**Returns:**

- `KmsKey`: The deleted key.

#### Encrypt Data with KMS Key

```python
encrypted_data = client.kms.encrypt_data(
    key_id="<key-id>",
    base64EncodedPlaintext="TXkgc2VjcmV0IG1lc3NhZ2U=" # must be base64 encoded
)
```

**Parameters:**

- `key_id` (str): The ID of the key to encrypt the data with.
- `base64EncodedPlaintext` (str): The plaintext data to encrypt (must be base64 encoded).

**Returns:**

- `str`: The encrypted ciphertext.

#### Decrypte Data with KMS Key

```python
decrypted_data = client.kms.decrypt_data(
    key_id="<key-id>",
    ciphertext="Aq96Ry7sMH3k/ogaIB5MiSfH+LblQRBu69lcJe0GfIvI48ZvbWY+9JulyoQYdjAx"
)
```

**Parameters:**

- `key_id` (str): The ID of the key to decrypt the data with.
- `ciphertext` (str): The ciphertext returned from the encrypt operation.

**Returns:**

- `str`: The base64 encoded plaintext.
