from typing import List, Union

from infisical_sdk.infisical_requests import InfisicalRequests
from infisical_sdk.api_types import (
    ListSecretsResponse,
    SingleSecretResponse,
    BaseSecret,
)
from infisical_sdk.util import SecretsCache

CACHE_KEY_LIST_SECRETS = "cache-list-secrets"
CACHE_KEY_SINGLE_SECRET = "cache-single-secret"


class V3RawSecrets:
    def __init__(self, requests: InfisicalRequests, cache: SecretsCache) -> None:
        self.requests = requests
        self.cache = cache

    def list_secrets(
        self,
        project_id: str,
        environment_slug: str,
        secret_path: str,
        expand_secret_references: bool = True,
        view_secret_value: bool = True,
        recursive: bool = False,
        include_imports: bool = True,
        tag_filters: List[str] = [],
    ) -> ListSecretsResponse:
        params = {
            "workspaceId": project_id,
            "environment": environment_slug,
            "secretPath": secret_path,
            "viewSecretValue": str(view_secret_value).lower(),
            "expandSecretReferences": str(expand_secret_references).lower(),
            "recursive": str(recursive).lower(),
            "include_imports": str(include_imports).lower(),
        }

        if tag_filters:
            params["tagSlugs"] = ",".join(tag_filters)

        cache_key = self.cache.compute_cache_key(CACHE_KEY_LIST_SECRETS, **params)
        if self.cache.enabled:
            cached_response = self.cache.get(cache_key)

            if cached_response is not None and isinstance(
                cached_response, ListSecretsResponse
            ):
                return cached_response

        result = self.requests.get(
            path="/api/v3/secrets/raw", params=params, model=ListSecretsResponse
        )

        if self.cache.enabled:
            self.cache.set(cache_key, result.data)

        return result.data

    def get_secret_by_name(
        self,
        secret_name: str,
        project_id: str,
        environment_slug: str,
        secret_path: str,
        expand_secret_references: bool = True,
        include_imports: bool = True,
        view_secret_value: bool = True,
        version: str = None,
    ) -> BaseSecret:
        params = {
            "workspaceId": project_id,
            "viewSecretValue": str(view_secret_value).lower(),
            "environment": environment_slug,
            "secretPath": secret_path,
            "expandSecretReferences": str(expand_secret_references).lower(),
            "include_imports": str(include_imports).lower(),
            "version": version,
        }

        cache_params = {
            "project_id": project_id,
            "environment_slug": environment_slug,
            "secret_path": secret_path,
            "secret_name": secret_name,
        }

        cache_key = self.cache.compute_cache_key(
            CACHE_KEY_SINGLE_SECRET, **cache_params
        )

        if self.cache.enabled:
            cached_response = self.cache.get(cache_key)

            if cached_response is not None and isinstance(cached_response, BaseSecret):
                return cached_response

        result = self.requests.get(
            path=f"/api/v3/secrets/raw/{secret_name}",
            params=params,
            model=SingleSecretResponse,
        )

        if self.cache.enabled:
            self.cache.set(cache_key, result.data.secret)

        return result.data.secret

    def create_secret_by_name(
        self,
        secret_name: str,
        project_id: str,
        secret_path: str,
        environment_slug: str,
        secret_value: str = None,
        secret_comment: str = None,
        skip_multiline_encoding: bool = False,
        secret_reminder_repeat_days: Union[float, int] = None,
        secret_reminder_note: str = None,
    ) -> BaseSecret:
        requestBody = {
            "workspaceId": project_id,
            "environment": environment_slug,
            "secretPath": secret_path,
            "secretValue": secret_value,
            "secretComment": secret_comment,
            "tagIds": None,
            "skipMultilineEncoding": skip_multiline_encoding,
            "type": "shared",
            "secretReminderRepeatDays": secret_reminder_repeat_days,
            "secretReminderNote": secret_reminder_note,
        }
        result = self.requests.post(
            path=f"/api/v3/secrets/raw/{secret_name}",
            json=requestBody,
            model=SingleSecretResponse,
        )

        if self.cache.enabled:
            cache_params = {
                "project_id": project_id,
                "environment_slug": environment_slug,
                "secret_path": secret_path,
                "secret_name": secret_name,
            }

            cache_key = self.cache.compute_cache_key(
                CACHE_KEY_SINGLE_SECRET, **cache_params
            )
            self.cache.set(cache_key, result.data.secret)

            # Invalidates all list secret cache
            self.cache.invalidate_operation(CACHE_KEY_LIST_SECRETS)

        return result.data.secret

    def update_secret_by_name(
        self,
        current_secret_name: str,
        project_id: str,
        secret_path: str,
        environment_slug: str,
        secret_value: str = None,
        secret_comment: str = None,
        skip_multiline_encoding: bool = False,
        secret_reminder_repeat_days: Union[float, int] = None,
        secret_reminder_note: str = None,
        new_secret_name: str = None,
    ) -> BaseSecret:
        requestBody = {
            "workspaceId": project_id,
            "environment": environment_slug,
            "secretPath": secret_path,
            "secretValue": secret_value,
            "secretComment": secret_comment,
            "newSecretName": new_secret_name,
            "tagIds": None,
            "skipMultilineEncoding": skip_multiline_encoding,
            "type": "shared",
            "secretReminderRepeatDays": secret_reminder_repeat_days,
            "secretReminderNote": secret_reminder_note,
        }

        result = self.requests.patch(
            path=f"/api/v3/secrets/raw/{current_secret_name}",
            json=requestBody,
            model=SingleSecretResponse,
        )

        if self.cache.enabled:
            cache_params = {
                "project_id": project_id,
                "environment_slug": environment_slug,
                "secret_path": secret_path,
                "secret_name": current_secret_name,
            }

            cache_key = self.cache.compute_cache_key(
                CACHE_KEY_SINGLE_SECRET, **cache_params
            )
            self.cache.unset(cache_key)

            # Invalidates all list secret cache
            self.cache.invalidate_operation(CACHE_KEY_LIST_SECRETS)

        return result.data.secret

    def delete_secret_by_name(
        self, secret_name: str, project_id: str, secret_path: str, environment_slug: str
    ) -> BaseSecret:
        requestBody = {
            "workspaceId": project_id,
            "environment": environment_slug,
            "secretPath": secret_path,
            "type": "shared",
        }

        result = self.requests.delete(
            path=f"/api/v3/secrets/raw/{secret_name}",
            json=requestBody,
            model=SingleSecretResponse,
        )

        if self.cache.enabled:
            cache_params = {
                "project_id": project_id,
                "environment_slug": environment_slug,
                "secret_path": secret_path,
                "secret_name": secret_name,
            }

            cache_key = self.cache.compute_cache_key(
                CACHE_KEY_SINGLE_SECRET, **cache_params
            )
            self.cache.unset(cache_key)

            # Invalidates all list secret cache
            self.cache.invalidate_operation(CACHE_KEY_LIST_SECRETS)

        return result.data.secret
