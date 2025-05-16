from typing import Optional, Union

from infisical_sdk.api_types import (
    ECDSASigningAlgorithm,
    KmsKey,
    KmsKeyDecryptDataResponse,
    KmsKeyEncryptDataResponse,
    KmsKeySignDataResponse,
    KmsKeysOrderBy,
    KmsKeyVerifyDataResponse,
    ListKmsKeysResponse,
    OrderDirection,
    RSASigningAlgorithm,
    SingleKmsKeyResponse,
    SymmetricEncryption,
)
from infisical_sdk.infisical_requests import InfisicalRequests


class ActiveKMSKey:
    def __init__(self, key_data: KmsKey, requests: InfisicalRequests):
        self._key_data: KmsKey = key_data
        self._key_type: KmsKey = key_data
        self._requests: InfisicalRequests = requests
        self.key_id: str = self._key_data.id

    @property
    def id(self) -> str:
        return self._key_data.id

    @property
    def description(self) -> str:
        return self._key_data.description

    @property
    def is_disabled(self) -> bool:
        return self._key_data.isDisabled

    @property
    def org_id(self) -> str:
        return self._key_data.orgId

    @property
    def name(self) -> str:
        return self._key_data.name

    @property
    def created_at(self) -> str:
        return self._key_data.createdAt

    @property
    def updated_at(self) -> str:
        return self._key_data.updatedAt

    @property
    def project_id(self) -> str:
        return self._key_data.projectId

    @property
    def version(self) -> int:
        return self._key_data.version

    @property
    def encryption_algorithm(self) -> SymmetricEncryption:
        return self._key_data.encryptionAlgorithm

    @property
    def raw_data(self) -> KmsKey:
        return self._key_data
    
    @property
    def full_id(self) -> str:
        return "%s.%s.%s" % (self.org_id, self.projectId, self.key_id)

    def encrypt_data(self, base64EncodedPlaintext: str) -> str:
        """
        Encrypt data with the specified KMS key.

        :param base64EncodedPlaintext: The base64 encoded plaintext to encrypt
        :type plaintext: str


        :return: The encrypted base64 encoded plaintext (ciphertext)
        :rtype: str
        """

        request_body = {"plaintext": base64EncodedPlaintext}
        response = self._requests.post(
            path=f"/api/v1/kms/keys/{self.key_id}/encrypt",
            json=request_body,
            model=KmsKeyEncryptDataResponse,
        )
        return response.data.ciphertext

    def decrypt_data(self, ciphertext: str) -> str:
        """
        Decrypt data with the specified KMS key.

        :param ciphertext: The encrypted base64 plaintext to decrypt
        :type ciphertext: str


        :return: The base64 encoded plaintext
        :rtype: str
        """

        request_body = {"ciphertext": ciphertext}
        response = self._requests.post(
            path=f"/api/v1/kms/keys/{self.key_id}/decrypt",
            json=request_body,
            model=KmsKeyDecryptDataResponse,
        )
        return response.data.plaintext

    def sign_data(
        self,
        base64EncodedPlaintext: str,
        signingAlgorithm: Union[ECDSASigningAlgorithm, RSASigningAlgorithm],
    ) -> str:
        """
        Sign the provided base64-encoded plaintext using the specified KMS key and signing algorithm.

        :param base64EncodedPlaintext: The base64-encoded plaintext to sign.
        :type base64EncodedPlaintext: str
        :param signingAlgorithm: The signing algorithm to use (RSA or ECDSA variants).
        :type signingAlgorithm: ECDSASigningAlgorithm | RSASigningAlgorithm

        :return: The base64-encoded signature.
        :rtype: str
        """
        request_body = {
            "data": base64EncodedPlaintext,
            "signingAlgorithm": signingAlgorithm.value,
        }
        response = self._requests.post(
            path=f"/api/v1/kms/keys/{self.key_id}/sign",
            json=request_body,
            model=KmsKeySignDataResponse,
        )
        return response.data.signature

    def verify_data(
        self,
        base64EncodedPlaintext: str,
        signingAlgorithm: Union[ECDSASigningAlgorithm, RSASigningAlgorithm],
        signature: str,
    ) -> bool:
        """
        Verify a signature for the given base64-encoded plaintext using the specified KMS key and signing algorithm.

        :param base64EncodedPlaintext: The base64-encoded plaintext whose signature is being verified.
        :type base64EncodedPlaintext: str
        :param signingAlgorithm: The algorithm used to generate the signature.
        :type signingAlgorithm: ECDSASigningAlgorithm | RSASigningAlgorithm
        :param signature: The base64-encoded signature to verify.
        :type signature: str

        :return: True if the signature is valid, False otherwise.
        :rtype: bool
        """
        request_body = {
            "data": base64EncodedPlaintext,
            "signingAlgorithm": signingAlgorithm.value,
            "signature": signature,
        }
        response = self._requests.post(
            path=f"/api/v1/kms/keys/{self.key_id}/verify",
            json=request_body,
            model=KmsKeyVerifyDataResponse,
        )
        return response.data.signatureValid

    def update(
        self,
        name: Optional[str] = None,
        is_disabled: Optional[bool] = None,
        description: Optional[
            str
        ] = None,
    ) -> "ActiveKMSKey":
        request_body = {}
        if name is not None:
            request_body["name"] = name
        if is_disabled is not None:
            request_body["isDisabled"] = is_disabled
        if description is not None:
            request_body["description"] = description

        if not request_body:
            return self

        response = self._requests.patch(
            path=f"/api/v1/kms/keys/{self.key_id}",
            json=request_body,
            model=SingleKmsKeyResponse,
        )
        self._key_data = response.data.key
        return self

    def delete(self) -> KmsKey:
        response = self._requests.delete(
            path=f"/api/v1/kms/keys/{self.key_id}",
            json={},
            model=SingleKmsKeyResponse,
        )
        return response.data.key

    def __repr__(self) -> str:
        return f"<ActiveKMSKey id='{self.id}' name='{self.name}'>"


class KMS:
    def __init__(self, requests: InfisicalRequests) -> None:
        self.requests = requests

    def list_keys(
        self,
        project_id: str,
        offset: int = 0,
        limit: int = 100,
        order_by: KmsKeysOrderBy = KmsKeysOrderBy.NAME,
        order_direction: OrderDirection = OrderDirection.ASC,
        search: Optional[str] = None,
    ) -> ListKmsKeysResponse:
        params = {
            "projectId": project_id,
            "offset": offset,
            "limit": limit,
            "orderBy": order_by,
            "orderDirection": order_direction,
        }
        if search is not None:
            params["search"] = search

        response = self.requests.get(
            path="/api/v1/kms/keys", params=params, model=ListKmsKeysResponse
        )
        return response.data

    def get_key_by_id(self, key_id: str) -> ActiveKMSKey:
        response = self.requests.get(
            path=f"/api/v1/kms/keys/{key_id}", model=SingleKmsKeyResponse
        )
        return ActiveKMSKey(key_data=response.data.key, requests=self.requests)

    def get_key_by_name(self, key_name: str, project_id: str) -> ActiveKMSKey:
        params = {"projectId": project_id}
        response = self.requests.get(
            path=f"/api/v1/kms/keys/key-name/{key_name}",
            params=params,
            model=SingleKmsKeyResponse,
        )
        return ActiveKMSKey(key_data=response.data.key, requests=self.requests)

    def create_key(
        self,
        name: str,
        project_id: str,
        encryption_algorithm: SymmetricEncryption,
        description: Optional[str] = None,
    ) -> ActiveKMSKey:
        request_body = {
            "name": name,
            "projectId": project_id,
            "encryptionAlgorithm": encryption_algorithm.value,
        }
        if description is not None:
            request_body["description"] = description

        response = self.requests.post(
            path="/api/v1/kms/keys", json=request_body, model=SingleKmsKeyResponse
        )
        return ActiveKMSKey(key_data=response.data.key, requests=self.requests)
