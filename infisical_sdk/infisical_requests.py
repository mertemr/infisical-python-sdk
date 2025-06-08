import functools
import random
import socket
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING, Any, Callable, Dict,
    Generic, List, Optional, Type, TypeVar
)

import httpx

if TYPE_CHECKING:
    from infisical_sdk.api_types import BaseModel

T = TypeVar("T")

# List of network-related exceptions that should trigger retries
NETWORK_ERRORS = [
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.ConnectTimeout,
    socket.gaierror,
    socket.timeout,
    ConnectionResetError,
    ConnectionRefusedError,
    ConnectionError,
    ConnectionAbortedError,
]


def join_url(base: str, path: str) -> str:
    """
    Join base URL and path properly, handling slashes appropriately.
    """
    if not base.endswith("/"):
        base += "/"
    return base + path.lstrip("/")


class InfisicalError(Exception):
    """Base exception for Infisical client errors"""

    pass


class APIError(InfisicalError):
    """API-specific errors"""

    def __init__(self, message: str, status_code: int, response: Dict[str, Any]):
        self.status_code = status_code
        self.response = response
        super().__init__(f"{message} (Status: {status_code})")


@dataclass
class APIResponse(Generic[T]):
    """Generic API response wrapper"""

    data: T
    status_code: int
    headers: Dict[str, str]

    def to_dict(self) -> Dict:
        """Convert to dictionary with camelCase keys"""
        return {
            "data": self.data.to_dict() if hasattr(self.data, "to_dict") else self.data,
            "statusCode": self.status_code,
            "headers": self.headers,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "APIResponse[T]":
        """Create from dictionary with camelCase keys"""
        return cls(
            data=data["data"], status_code=data["statusCode"], headers=data["headers"]
        )


def with_retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    network_errors: Optional[List[Type[Exception]]] = None,
) -> Callable:
    """
    Decorator to add retry logic with exponential backoff to requests methods.
    """
    if network_errors is None:
        network_errors = NETWORK_ERRORS

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retry_count = 0

            while True:
                try:
                    return func(*args, **kwargs)
                except tuple(network_errors):
                    retry_count += 1
                    if retry_count > max_retries:
                        raise

                    base_delay_with_backoff = base_delay * (2 ** (retry_count - 1))

                    # +/-20% jitter
                    jitter = random.uniform(-0.2, 0.2) * base_delay_with_backoff
                    delay = base_delay_with_backoff + jitter

                    time.sleep(delay)

        return wrapper

    return decorator


class InfisicalRequests:
    def __init__(
        self,
        host: str,
        token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[httpx.Timeout] = None
    ):
        """Initialize InfisicalRequests client

        Args:
            host (str): Base URL for the Infisical API (without trailing slash)
            token (Optional[str], optional): Bearer token to authorize client. Defaults to None. `Alternative to universal_auth`
            headers (Optional[Dict[str, str]], optional): Custom headers to pass client. Defaults to None.
        """
        self.headers = {
            "User-Agent": "Infisical Python SDK/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if headers:
            self.headers.update(headers)
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

        if not timeout:
            timeout = httpx.Timeout(10.0, connect=5.0)

        self.host = host.rstrip("/")
        self.session = httpx.Client(
            base_url=self.host,
            timeout=timeout,
            follow_redirects=True,
            headers=self.headers,
        )

    def set_token(self, token: str):
        self.headers["Authorization"] = f"Bearer {token}"
        self.session.headers["Authorization"] = self.headers["Authorization"]

    def _handle_response(self, response: httpx.Response, model: Type["BaseModel"]) -> APIResponse:
        """Handle API response and raise appropriate errors"""
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            error_data = {"message": response.text}
            with suppress(ValueError):
                error_data = response.json()
            raise APIError(
                message=error_data.get("message", "Unknown error"),
                status_code=response.status_code,
                response=error_data,
            ) from e

        try:
            data = response.json()
        except ValueError:  # response.json() parsing error
            raise InfisicalError("Invalid JSON response") from None

        parsed_data = self._handle_data(data, model)
        return APIResponse(
            data=parsed_data, status_code=response.status_code, headers=response.headers
        )

    def _handle_data(self, data: Dict[str, Any], model: Type["BaseModel"]) -> Dict[str, Any]:
        if hasattr(model, "from_dict"):
            return model.from_dict(data)

        return data
    
    def _filter_none_values(json: dict[str, Any] | None) -> dict[str, Any] | None:
        if json is not None:
            # Filter out None values
            json = {k: v for k, v in json.items() if v is not None}
        return json

    @with_retry(max_retries=4, base_delay=1.0)
    def get(
        self, path: str, model: Type[T], params: Optional[Dict[str, Any]] = None
    ) -> APIResponse[T]:
        """
        Make a GET request and parse response into given model

        Args:
            path: API endpoint path
            model: model class to parse response into
            params: Optional query parameters
        """
        response = self.session.get(path, params=params)
        return self._handle_response(response, model)

    @with_retry(max_retries=4, base_delay=1.0)
    def post(
        self, path: str, model: Type[T], json: Optional[Dict[str, Any]] = None
    ) -> APIResponse[T]:
        """Make a POST request with JSON data"""

        filtered_json = self._filter_none_values(json)
        response = self.session.post(path, json=filtered_json)
        return self._handle_response(response, model)

    @with_retry(max_retries=4, base_delay=1.0)
    def patch(
        self, path: str, model: Type[T], json: Optional[Dict[str, Any]] = None
    ) -> APIResponse[T]:
        """Make a PATCH request with JSON data"""

        filtered_json = self._filter_none_values(json)
        response = self.session.patch(path, json=filtered_json)
        return self._handle_response(response, model)

    @with_retry(max_retries=4, base_delay=1.0)
    def delete(
        self, path: str, model: Type[T], json: Optional[Dict[str, Any]] = None
    ) -> APIResponse[T]:
        """Make a DELETE request with JSON data"""

        filtered_json = self._filter_none_values(json)
        response = self.session.delete(path, json=filtered_json)
        return self._handle_response(response, model)
