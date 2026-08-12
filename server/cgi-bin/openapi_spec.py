"""
RemotePower OpenAPI 3.1 specification.

This module generates the OpenAPI document served at ``/api/openapi.json`` and
rendered by the Swagger UI page at ``/swagger.html``.

It's hand-written because the CGI dispatch table in :mod:`api` is just an
``elif`` chain over ``path_info``/``method`` — there's no decorator metadata
to introspect, and writing one would buy us nothing except a different way
to be wrong about response shapes. Hand-writing it keeps the spec honest:
when an endpoint changes, the spec changes with it. We also enforce a
keep-it-current discipline by including the spec in the test suite.

The spec covers the public-facing handlers: device CRUD, command queueing,
auth, CMDB, vault, update logs, and the various reporting endpoints. It
deliberately does not document the agent-only endpoints (``/api/heartbeat``,
``/api/enroll``) because users of the Swagger UI are humans, not agents,
and exposing them just adds noise.
"""

from __future__ import annotations

import re
from typing import Any


def _security_schemes() -> dict[str, Any]:
    """Two interchangeable auth options: session token from login, or API key."""
    return {
        "SessionToken": {
            "type": "apiKey",
            "in": "header",
            "name": "X-Token",
            "description": (
                "Session token returned by ``POST /api/login``. "
                "Sent on every authenticated request."
            ),
        },
        "ApiKey": {
            "type": "apiKey",
            "in": "header",
            "name": "X-Token",
            "description": (
                "API key created in the API Keys tab. Same header as session "
                "tokens — the server distinguishes by lookup."
            ),
        },
        "VaultKey": {
            "type": "apiKey",
            "in": "header",
            "name": "X-RP-Vault-Key",
            "description": (
                "Hex-encoded 32-byte AES-GCM key derived from the CMDB vault "
                "passphrase. Required for credential write/reveal operations."
            ),
        },
    }


def _common_responses() -> dict[str, Any]:
    return {
        "Unauthorized": {
            "description": "Missing or invalid auth token.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
        },
        "NotFound": {
            "description": "Resource does not exist.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
        },
        "BadRequest": {
            "description": "Validation failure on the request body or parameters.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
        },
        "VaultLocked": {
            "description": (
                "Vault key required but not provided. The response body's "
                "``code`` field is ``vault_locked``."
            ),
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
        },
    }


def _device_command_responses() -> dict[str, Any]:
    """Shared response set for the four device-command endpoints (shutdown/
    reboot/upgrade-device/update-device). A whole responses MAP has no valid
    $ref target in OpenAPI 3.x (only individual components/responses entries
    do) -- returns a fresh dict per call so each operation gets its own copy,
    not a shared mutable reference."""
    return {
        "200": {
            "description": "Queued.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Ok"}}},
        },
        "400": {"$ref": "#/components/responses/BadRequest"},
        "401": {"$ref": "#/components/responses/Unauthorized"},
    }


def _common_request_bodies() -> dict[str, Any]:
    # v6.1.1: /reboot, /upgrade-device and /update-device used to $ref this
    # shape via "#/paths/~1shutdown/post/requestBody" -- OpenAPI's requestBody
    # field DOES support a $ref, but only into components/requestBodies (or an
    # inline object); a $ref into #/paths/... is not a valid target for any
    # spec-consuming tool (confirmed: it fails validation in openapi-python-
    # client, the codegen tool this now backs). Extracted here so the ref is
    # actually valid and the four commands share one definition for real.
    return {
        "DeviceCommand": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "device_id": {"type": "string"},
                            "device_ids": {"type": "array", "items": {"type": "string"}},
                            "tag": {"type": "string"},
                            "group": {"type": "string"},
                        },
                    }
                }
            },
        },
    }


def _schemas() -> dict[str, Any]:
    return {
        "Error": {
            "type": "object",
            "properties": {
                "error": {"type": "string", "description": "Human-readable error message."},
                "code": {
                    "type": "string",
                    "description": "Machine-parseable error code (when applicable).",
                },
            },
            "required": ["error"],
        },
        "Ok": {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
        },
        "Device": {
            "type": "object",
            "description": "An enrolled device, keyed by ``device_id``.",
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "hostname": {"type": "string"},
                "ip": {"type": "string"},
                "mac": {"type": "string"},
                "os": {"type": "string"},
                "version": {"type": "string", "description": "Agent version."},
                "last_seen": {
                    "type": "integer",
                    "format": "int64",
                    "description": "Unix timestamp.",
                },
                "enrolled": {"type": "integer", "format": "int64"},
                "online": {"type": "boolean"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "group": {"type": "string"},
                "notes": {"type": "string"},
                "poll_interval": {"type": "integer", "minimum": 10, "maximum": 3600},
            },
        },
        "CmdbAsset": {
            "type": "object",
            "properties": {
                "device_id": {"type": "string"},
                "name": {"type": "string"},
                "asset_id": {"type": "string", "maxLength": 64},
                "server_function": {"type": "string", "maxLength": 64},
                "hypervisor_url": {"type": "string", "maxLength": 512, "format": "uri"},
                "ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "documentation": {"type": "string", "maxLength": 65536},
                "has_documentation": {"type": "boolean"},
                "credential_count": {"type": "integer"},
            },
        },
        "CmdbAssetUpdate": {
            "type": "object",
            "description": "Patch payload — send only the fields you want to change.",
            "properties": {
                "asset_id": {"type": "string", "maxLength": 64},
                "server_function": {"type": "string", "maxLength": 64},
                "hypervisor_url": {"type": "string", "maxLength": 512, "format": "uri"},
                "ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "documentation": {"type": "string", "maxLength": 65536},
            },
        },
        "Credential": {
            "type": "object",
            "description": (
                "A credential's plaintext-safe metadata. The encrypted "
                "password is never returned by list endpoints; only by "
                "the dedicated ``/reveal`` endpoint."
            ),
            "properties": {
                "id": {"type": "string"},
                "label": {"type": "string", "maxLength": 64},
                "username": {"type": "string", "maxLength": 128},
                "note": {"type": "string", "maxLength": 512},
                "created_by": {"type": "string"},
                "created_at": {"type": "integer"},
                "updated_by": {"type": "string"},
                "updated_at": {"type": "integer"},
            },
        },
        "CredentialCreate": {
            "type": "object",
            "required": ["label", "password"],
            "properties": {
                "label": {"type": "string", "maxLength": 64},
                "username": {"type": "string", "maxLength": 128},
                "password": {
                    "type": "string",
                    "maxLength": 1024,
                    "description": "Plaintext — will be encrypted server-side.",
                },
                "note": {"type": "string", "maxLength": 512},
            },
        },
        "CredentialReveal": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"},
                "id": {"type": "string"},
                "label": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string", "description": "Decrypted plaintext."},
                "note": {"type": "string"},
            },
        },
        "VaultStatus": {
            "type": "object",
            "properties": {
                "configured": {"type": "boolean"},
                "kdf": {"type": "string", "enum": ["pbkdf2-sha256"], "nullable": True},
                "iterations": {"type": "integer", "nullable": True},
                "created_at": {"type": "integer", "nullable": True},
                "created_by": {"type": "string", "nullable": True},
            },
            "required": ["configured"],
        },
        "VaultPassphrase": {
            "type": "object",
            "required": ["passphrase"],
            "properties": {
                "passphrase": {"type": "string", "minLength": 12, "maxLength": 256},
            },
        },
        "VaultRotate": {
            "type": "object",
            "required": ["old_passphrase", "new_passphrase"],
            "properties": {
                "old_passphrase": {"type": "string"},
                "new_passphrase": {"type": "string", "minLength": 12, "maxLength": 256},
            },
        },
        "VaultKeyResponse": {
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"},
                "key": {"type": "string", "description": "Hex-encoded 32-byte AES-GCM key."},
                "rotated": {
                    "type": "integer",
                    "description": "Only on /change — number of credentials re-encrypted.",
                },
            },
        },
        "UpdateLogEntry": {
            "type": "object",
            "properties": {
                "started_at": {"type": "integer"},
                "finished_at": {"type": "integer"},
                "exit_code": {"type": "integer"},
                "output": {"type": "string"},
                "package_manager": {"type": "string", "enum": ["apt", "dnf", "pacman", "unknown"]},
                "triggered_by": {"type": "string"},
            },
        },
        "UpdateLogsResponse": {
            "type": "object",
            "properties": {
                "device_id": {"type": "string"},
                "name": {"type": "string"},
                "capacity": {"type": "integer"},
                "logs": {"type": "array", "items": {"$ref": "#/components/schemas/UpdateLogEntry"}},
            },
        },
        "LoginRequest": {
            "type": "object",
            "required": ["username", "password"],
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
                "totp": {"type": "string", "description": "TOTP code if 2FA is enabled."},
                "remember": {"type": "boolean", "description": "30-day session if true."},
            },
        },
        "LoginResponse": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "user": {"type": "string"},
                "role": {"type": "string", "enum": ["admin", "viewer"]},
            },
        },
    }


def _path_devices() -> dict[str, Any]:
    return {
        "/devices": {
            "get": {
                "tags": ["Devices"],
                "summary": "List enrolled devices",
                "operationId": "listDevices",
                "responses": {
                    "200": {
                        "description": "All enrolled devices.",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Device"},
                                }
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                },
            }
        },
        "/devices/{device_id}": {
            "delete": {
                "tags": ["Devices"],
                "summary": "Remove an enrolled device",
                "operationId": "deleteDevice",
                "parameters": [
                    {
                        "name": "device_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Ok"}}
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            }
        },
        "/devices/{device_id}/update-logs": {
            "get": {
                "tags": ["Devices"],
                "summary": "Get the rolling buffer of package-upgrade output",
                "description": (
                    "Returns the most recent runs of the `apt-get -y upgrade` / "
                    "`dnf -y upgrade` / `pacman -Syu` command on this device. "
                    "Capped at 10 entries by default; new runs evict the oldest."
                ),
                "operationId": "getUpdateLogs",
                "parameters": [
                    {
                        "name": "device_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "The device's update history.",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UpdateLogsResponse"}
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            }
        },
        "/shutdown": {
            "post": {
                "tags": ["Commands"],
                "summary": "Queue a shutdown on one or more devices",
                "operationId": "queueShutdown",
                "requestBody": {"$ref": "#/components/requestBodies/DeviceCommand"},
                "responses": _device_command_responses(),
            }
        },
        "/reboot": {
            "post": {
                "tags": ["Commands"],
                "summary": "Queue a reboot on one or more devices",
                "operationId": "queueReboot",
                "requestBody": {"$ref": "#/components/requestBodies/DeviceCommand"},
                "responses": _device_command_responses(),
            }
        },
        "/upgrade-device": {
            "post": {
                "tags": ["Commands"],
                "summary": "Queue an OS package upgrade (apt/dnf/pacman)",
                "description": (
                    "Output is captured and surfaced via "
                    "``GET /api/devices/{id}/update-logs`` after the next heartbeat."
                ),
                "operationId": "queueUpgrade",
                "requestBody": {"$ref": "#/components/requestBodies/DeviceCommand"},
                "responses": _device_command_responses(),
            }
        },
        "/update-device": {
            "post": {
                "tags": ["Commands"],
                "summary": "Push agent self-update on one or more devices",
                "operationId": "queueAgentUpdate",
                "requestBody": {"$ref": "#/components/requestBodies/DeviceCommand"},
                "responses": _device_command_responses(),
            }
        },
    }


def _path_cmdb() -> dict[str, Any]:
    return {
        "/cmdb": {
            "get": {
                "tags": ["CMDB"],
                "summary": "List assets with metadata",
                "operationId": "listCmdb",
                "parameters": [
                    {
                        "name": "q",
                        "in": "query",
                        "schema": {"type": "string"},
                        "description": "Free-text filter across name/hostname/asset_id/IP/function/docs.",
                    },
                    {
                        "name": "function",
                        "in": "query",
                        "schema": {"type": "string"},
                        "description": "Exact match on server_function.",
                    },
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/CmdbAsset"},
                                }
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                },
            }
        },
        "/cmdb/{device_id}": {
            "get": {
                "tags": ["CMDB"],
                "summary": "Get full asset detail (credentials redacted)",
                "operationId": "getCmdbAsset",
                "parameters": [
                    {
                        "name": "device_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CmdbAsset"}
                            }
                        },
                        "description": "OK",
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            },
            "put": {
                "tags": ["CMDB"],
                "summary": "Patch asset metadata",
                "operationId": "updateCmdbAsset",
                "parameters": [
                    {
                        "name": "device_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/CmdbAssetUpdate"}
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Ok"}}
                        },
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            },
        },
        "/cmdb/server-functions": {
            "get": {
                "tags": ["CMDB"],
                "summary": "Distinct server_function values for autocomplete",
                "operationId": "listServerFunctions",
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                }
                            }
                        },
                    }
                },
            }
        },
    }


def _path_vault() -> dict[str, Any]:
    return {
        "/cmdb/vault/status": {
            "get": {
                "tags": ["Vault"],
                "summary": "Vault setup state",
                "operationId": "getVaultStatus",
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/VaultStatus"}
                            }
                        },
                    }
                },
            }
        },
        "/cmdb/vault/setup": {
            "post": {
                "tags": ["Vault"],
                "summary": "Initialise the vault (one-shot, admin only)",
                "operationId": "setupVault",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/VaultPassphrase"}
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/VaultKeyResponse"}
                            }
                        },
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "409": {"description": "Vault already configured."},
                },
            }
        },
        "/cmdb/vault/unlock": {
            "post": {
                "tags": ["Vault"],
                "summary": "Derive the vault key from the passphrase",
                "operationId": "unlockVault",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/VaultPassphrase"}
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/VaultKeyResponse"}
                            }
                        },
                    },
                    "403": {"description": "Invalid passphrase. Audit-logged."},
                    "409": {"description": "Vault not yet configured."},
                },
            }
        },
        "/cmdb/vault/change": {
            "post": {
                "tags": ["Vault"],
                "summary": "Rotate passphrase + re-encrypt all credentials",
                "operationId": "rotateVault",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/VaultRotate"}}
                    },
                },
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/VaultKeyResponse"}
                            }
                        },
                    },
                    "403": {"description": "Invalid old passphrase."},
                },
            }
        },
        "/cmdb/{device_id}/credentials": {
            "get": {
                "tags": ["Credentials"],
                "summary": "List credentials (metadata only)",
                "operationId": "listCredentials",
                "parameters": [
                    {
                        "name": "device_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "credentials": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/Credential"},
                                        }
                                    },
                                }
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            },
            "post": {
                "tags": ["Credentials"],
                "summary": "Create a credential (admin + vault key)",
                "operationId": "createCredential",
                "security": [{"SessionToken": [], "VaultKey": []}],
                "parameters": [
                    {
                        "name": "device_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/CredentialCreate"}
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Created",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "ok": {"type": "boolean"},
                                        "id": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/VaultLocked"},
                    "403": {"description": "Invalid vault key, or non-admin."},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            },
        },
        "/cmdb/{device_id}/credentials/{cred_id}": {
            "put": {
                "tags": ["Credentials"],
                "summary": "Update a credential's metadata or password",
                "operationId": "updateCredential",
                "security": [{"SessionToken": []}, {"SessionToken": [], "VaultKey": []}],
                "parameters": [
                    {
                        "name": "device_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "cred_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "description": "Send only the fields you're changing. ``password`` requires X-RP-Vault-Key.",
                                "properties": {
                                    "label": {"type": "string"},
                                    "username": {"type": "string"},
                                    "password": {"type": "string"},
                                    "note": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Ok"}}
                        },
                    },
                    "401": {"$ref": "#/components/responses/VaultLocked"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            },
            "delete": {
                "tags": ["Credentials"],
                "summary": "Hard-delete a credential",
                "operationId": "deleteCredential",
                "parameters": [
                    {
                        "name": "device_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "cred_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Ok"}}
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            },
        },
        "/cmdb/{device_id}/credentials/{cred_id}/reveal": {
            "post": {
                "tags": ["Credentials"],
                "summary": "Decrypt and return a credential's plaintext password",
                "description": "Audit-logged. Requires admin role + valid vault key.",
                "operationId": "revealCredential",
                "security": [{"SessionToken": [], "VaultKey": []}],
                "parameters": [
                    {
                        "name": "device_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "cred_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Plaintext returned (audit-logged).",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CredentialReveal"}
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/VaultLocked"},
                    "403": {"description": "Bad vault key or non-admin."},
                    "404": {"$ref": "#/components/responses/NotFound"},
                },
            }
        },
    }


def _path_auth_misc() -> dict[str, Any]:
    return {
        "/login": {
            "post": {
                "tags": ["Auth"],
                "summary": "Authenticate and receive a session token",
                "operationId": "login",
                "security": [],  # public — this *creates* the token
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/LoginRequest"}
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LoginResponse"}
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "429": {"description": "Rate-limited (too many failed attempts)."},
                },
            }
        },
        "/logout": {
            "post": {
                "tags": ["Auth"],
                "summary": "Invalidate the current session token",
                "operationId": "logout",
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Ok"}}
                        },
                    }
                },
            }
        },
        "/audit-log": {
            "get": {
                "tags": ["Auth"],
                "summary": "Retrieve the audit log",
                "operationId": "getAuditLog",
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "ts": {"type": "integer"},
                                            "actor": {"type": "string"},
                                            "action": {"type": "string"},
                                            "detail": {"type": "string"},
                                            "source_ip": {"type": "string"},
                                        },
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/metrics": {
            "get": {
                "tags": ["Reporting"],
                "summary": "Prometheus metrics in text exposition format",
                "operationId": "prometheusMetrics",
                "responses": {"200": {"description": "OK", "content": {"text/plain": {}}}},
            }
        },
        "/about": {
            "get": {
                "tags": ["Reporting"],
                "summary": "Server build metadata",
                "operationId": "about",
                "responses": {"200": {"description": "OK", "content": {"application/json": {}}}},
            }
        },
        # ── v4.1.0: per-host Checks + background CVE scan ──
        "/checks": {
            "get": {
                "tags": ["Checks"],
                "summary": "Fleet check matrix (OK/WARN/CRIT/UNKNOWN per host)",
                "operationId": "fleetChecks",
                "parameters": [
                    {
                        "name": "status",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string", "enum": ["critical", "warning"]},
                    }
                ],
                "responses": {"200": {"description": "OK", "content": {"application/json": {}}}},
            }
        },
        "/checks/toggle": {
            "post": {
                "tags": ["Checks"],
                "summary": "Mute/unmute a check on a host (admin)",
                "operationId": "toggleCheck",
                "responses": {"200": {"description": "OK", "content": {"application/json": {}}}},
            }
        },
        "/checks/custom": {
            "get": {
                "tags": ["Checks"],
                "summary": "List custom-check definitions",
                "operationId": "listCustomChecks",
                "responses": {"200": {"description": "OK", "content": {"application/json": {}}}},
            },
            "post": {
                "tags": ["Checks"],
                "summary": "Add/update a custom check (process/port/file/job/log) — admin",
                "operationId": "saveCustomCheck",
                "responses": {"200": {"description": "OK", "content": {"application/json": {}}}},
            },
        },
        "/cve/scan": {
            "post": {
                "tags": ["CVE"],
                "summary": "Queue a background CVE scan (one device or the whole fleet)",
                "description": "Returns 202 immediately; the scan runs in a detached "
                "process. Poll /api/cve/scan-status for progress.",
                "operationId": "cveScan",
                "responses": {
                    "202": {"description": "Scan queued", "content": {"application/json": {}}},
                    "409": {"description": "A scan is already running"},
                },
            }
        },
        "/cve/scan-status": {
            "get": {
                "tags": ["CVE"],
                "summary": "Progress of the background CVE scan",
                "operationId": "cveScanStatus",
                "responses": {"200": {"description": "OK", "content": {"application/json": {}}}},
            }
        },
    }


# v6.4.3: one endpoint, one entry — see _stub_operations. Compiled once.
_TEMPLATE_SEG = re.compile(r"\{[^}]+\}")


def _stub_operations(paths: dict[str, Any], routes: list[tuple[str, str]] | None) -> None:
    """v5.4.1 (E1): fill a minimal valid operation for every registered route the
    hand-written specs above don't already cover, so the document describes 100%
    of the API surface (not just the ~28 richly-documented endpoints). ``routes``
    is the caller's ``(METHOD, '/api/<path>')`` table; the ``/api`` prefix is
    stripped to match this document's server-relative paths. Routes with a path
    template (``{id}``) are left to the hand-written specs (they declare the path
    parameters), so only literal paths are stubbed."""
    if not routes:
        return
    # v6.4.3: a hand-written spec and the dispatcher reconstruction can name the
    # SAME endpoint with different parameter names — `_path_ingest` documents
    # `/itsm/in/{token}` while the reconstruction derives `/itsm/in/{id}` from
    # the same branch. Stubbing the second one renders one endpoint twice in
    # Swagger with no way to tell which name is real. Identity is the path
    # SHAPE (literal segments, parameter names erased); the hand-written entry
    # always wins, since it is the one that documents the parameter.
    _shape = lambda p: _TEMPLATE_SEG.sub("{}", p)  # noqa: E731
    documented_shapes = {_shape(p): p for p in paths}
    for method, full in routes:
        m = str(method).lower()
        if m not in ("get", "post", "put", "patch", "delete"):
            continue
        rel = full[4:] if full.startswith("/api") else full
        if not rel:
            continue
        canonical = documented_shapes.get(_shape(rel))
        if canonical and canonical != rel:
            rel = canonical
        op = paths.setdefault(rel, {})
        documented_shapes.setdefault(_shape(rel), rel)
        if m in op:
            continue  # already richly documented — never overwrite
        # v5.6.0: templated paths (`/x/{id}`) used to be skipped, leaving the
        # whole `{id}` surface undocumented. Now they get a stub too, with each
        # `{name}` segment declared as a required string path parameter.
        params = [
            {"name": seg[1:-1], "in": "path", "required": True, "schema": {"type": "string"}}
            for seg in rel.split("/")
            if seg.startswith("{") and seg.endswith("}")
        ]
        op[m] = {
            "summary": f"{method.upper()} {rel}",
            "tags": ["Other"],
            "description": (
                "Auto-generated stub — see the in-app docs / source for the "
                "full request and response shape."
            ),
            "responses": {
                "200": {"description": "Success"},
                "401": {"$ref": "#/components/responses/Unauthorized"},
            },
        }
        if params:
            op[m]["parameters"] = params


def _path_virt() -> dict[str, Any]:
    """v5.6.0: virtualization lifecycle across Proxmox/vSphere/OpenShift/vCloud."""
    _id = {
        "name": "id",
        "in": "path",
        "required": True,
        "schema": {"type": "string"},
        "description": "Integration instance id from GET /api/virt/platforms.",
    }
    _ok = {"200": {"description": "OK"}, "401": {"$ref": "#/components/responses/Unauthorized"}}
    _admin = {
        "200": {"description": "OK"},
        "401": {"$ref": "#/components/responses/Unauthorized"},
        "403": {"description": "Admin role required."},
        "404": {"description": "Platform not found."},
    }
    return {
        "/virt/platforms": {
            "get": {
                "tags": ["Virtualization"],
                "summary": "List lifecycle-capable virtualization platforms",
                "description": (
                    "Returns the configured virtualization integrations "
                    "(vCenter/vSphere, VMware Cloud Director, OpenShift) with their "
                    "id, label, type and supported power actions. No secrets."
                ),
                "operationId": "listVirtPlatforms",
                "responses": _ok,
            }
        },
        "/virt/{id}/vms": {
            "get": {
                "tags": ["Virtualization"],
                "summary": "List guests on a platform",
                "operationId": "listVirtVms",
                "parameters": [_id],
                "responses": _ok,
            }
        },
        "/virt/{id}/power": {
            "post": {
                "tags": ["Virtualization"],
                "summary": "Power action on a guest (admin, audited)",
                "operationId": "virtPower",
                "parameters": [_id],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["vm_id", "action"],
                                "properties": {
                                    "vm_id": {"type": "string"},
                                    "action": {
                                        "type": "string",
                                        "enum": [
                                            "start",
                                            "stop",
                                            "shutdown",
                                            "reboot",
                                            "reset",
                                            "suspend",
                                            "restart",
                                        ],
                                    },
                                },
                            }
                        }
                    },
                },
                "responses": _admin,
            }
        },
        "/virt/{id}/snapshots": {
            "get": {
                "tags": ["Virtualization"],
                "summary": "List snapshots for one guest",
                "operationId": "listVirtSnapshots",
                "parameters": [
                    _id,
                    {"name": "vm", "in": "query", "required": True, "schema": {"type": "string"}},
                ],
                "responses": _ok,
            }
        },
        "/virt/{id}/snapshot": {
            "post": {
                "tags": ["Virtualization"],
                "summary": "Create / revert / delete a snapshot (admin, audited)",
                "operationId": "virtSnapshotAction",
                "parameters": [_id],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["vm_id", "action"],
                                "properties": {
                                    "vm_id": {"type": "string"},
                                    "action": {
                                        "type": "string",
                                        "enum": ["create", "revert", "delete"],
                                    },
                                    "name": {"type": "string"},
                                    "desc": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "responses": _admin,
            }
        },
    }


def _path_identity() -> dict[str, Any]:
    """v6.4.3: SCIM 2.0 and agent self-registration — the other any-method
    branches the reconstruction skips.

    Same root cause as `_path_ingest` below: `_dispatcher_routes` reconstructs a
    path only from an explicit `m == '<VERB>'` in the branch condition, and
    these enforce the method inside the handler instead. SCIM is the worst of
    the remainder to leave out, because it is a *standards-defined* surface that
    an administrator points an identity provider at — RFC 7644 says where the
    endpoints live, but not which of them this server actually implements, and
    the answer here is deliberately partial (groups are read-only; roles are
    defined in RemotePower, not created by the IdP).

    Methods are taken from what each handler ENFORCES, not guessed.
    """
    _scim_err = {
        "401": {"description": "Missing or invalid SCIM bearer token."},
        "403": {"description": "SCIM provisioning is not enabled."},
    }

    def _scim(summary: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        op: dict[str, Any] = {
            "tags": ["SCIM"],
            "summary": summary,
            "responses": {"200": {"description": "SCIM resource."}, **_scim_err},
        }
        if extra:
            op.update(extra)
        return op

    _filter = [
        {
            "name": "filter",
            "in": "query",
            "required": False,
            "schema": {"type": "string"},
            "description": 'SCIM filter. Only `attr eq "value"` is supported.',
        }
    ]
    return {
        "/enroll/register": {
            "post": {
                "tags": ["Agents"],
                "summary": "Agent self-registration against an enrollment token",
                "description": (
                    "Exchanges a one-time enrollment token for a per-device "
                    "agent token. Called by the installer, not by operators."
                ),
                "responses": {
                    "200": {"description": "Registered; returns the device token."},
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "403": {"description": "Unknown, expired or already-used token."},
                },
            }
        },
        "/scim/v2/Users": {
            "get": _scim("List provisioned users", {"parameters": _filter}),
            "post": _scim(
                "Provision a user",
                {"responses": {"201": {"description": "Created."}, **_scim_err}},
            ),
        },
        "/scim/v2/Groups": {
            "get": _scim(
                "List role-groups (RemotePower roles, mapped as SCIM groups)",
                {"parameters": _filter},
            ),
        },
        "/scim/v2/ServiceProviderConfig": {
            "get": _scim("Advertise which SCIM features this server supports")
        },
        "/scim/v2/ResourceTypes": {"get": _scim("List supported SCIM resource types")},
        "/scim/v2/Schemas": {"get": _scim("SCIM User and Group schemas as implemented")},
    }


def _path_ingest() -> dict[str, Any]:
    """v6.4.3: the agent heartbeat and the four token-in-path ingest endpoints.

    Every one of these was ABSENT from the published spec. `_dispatcher_routes`
    reconstructs a path only when the branch carries an explicit `m == '<VERB>'`,
    and these accept any method, so the stub pass skipped them silently — which
    is the documented behaviour and also why nobody noticed.

    They are the worst possible omissions to have. `/heartbeat` is the endpoint
    every agent in the fleet calls, and the four ingest paths are precisely what
    an operator integrates a syslog daemon, a webhook, an SNMP trap sink or an
    ITSM tool against. A spec that documents 660 paths and not these is
    complete everywhere except where someone would actually look.
    """
    _tok = {
        "name": "token",
        "in": "path",
        "required": True,
        "schema": {"type": "string"},
        "description": (
            "Per-source ingest token minted in the UI. It is the "
            "ONLY credential on these endpoints — they are "
            "deliberately unauthenticated otherwise so an appliance "
            "that cannot send headers can still deliver."
        ),
    }
    _ok = {
        "200": {"description": "Accepted."},
        "400": {"description": "Malformed body."},
        "403": {"description": "Unknown or revoked ingest token."},
    }
    return {
        "/heartbeat": {
            "post": {
                "tags": ["Agents"],
                "summary": "Agent heartbeat (telemetry in, work out)",
                "description": (
                    "The endpoint every agent calls on its poll interval. The "
                    "request carries the host's telemetry; the response carries "
                    "the work queued for it — a pending command, one-shot force "
                    "flags, agent-side check definitions and cadence hints.\n\n"
                    "Authenticated with the device token issued at enrolment, "
                    "sent as `X-Token`. Bodies are sanitised server-side before "
                    "storage: fields the server does not model are dropped."
                ),
                "security": [{"DeviceToken": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "device_id": {"type": "string"},
                                    "sysinfo": {"type": "object", "description": "Host telemetry."},
                                    "delta": {
                                        "type": "boolean",
                                        "description": "Body carries only fields "
                                        "changed since the last beat.",
                                    },
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {"description": "Work for this agent, if any."},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "404": {"description": "Unknown device."},
                },
            }
        },
        "/syslog/in/{token}": {
            "post": {
                "tags": ["Ingest"],
                "summary": "Inbound syslog lines",
                "description": (
                    "Accepts `{lines: [...]}` OR a bare JSON array "
                    "of lines — both shapes are supported on "
                    "purpose, because forwarders differ."
                ),
                "parameters": [_tok],
                "responses": _ok,
            }
        },
        "/snmp/trap/{token}": {
            "post": {
                "tags": ["Ingest"],
                "summary": "Inbound SNMP traps",
                "description": ("Accepts `{traps: [...]}` OR a bare JSON array."),
                "parameters": [_tok],
                "responses": _ok,
            }
        },
        "/webhook/in/{token}": {
            "post": {
                "tags": ["Ingest"],
                "summary": "Inbound webhook from a third-party system",
                "parameters": [_tok],
                "responses": _ok,
            }
        },
        "/itsm/in/{token}": {
            "post": {
                "tags": ["Ingest"],
                "summary": "Inbound ITSM ticket event",
                "parameters": [_tok],
                "responses": _ok,
            }
        },
    }


def build_spec(server_version: str, routes: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    """Return the full OpenAPI 3.1 document.

    Args:
        server_version: The current ``SERVER_VERSION`` string from
            :mod:`api`. Embedded as the spec's ``info.version``.
        routes: Optional ``(METHOD, '/api/<path>')`` table (e.g.
            ``api._build_exact_routes()`` keys). Every literal route not already
            richly documented gets a minimal stub so the spec covers the whole
            API surface (v5.4.1, E1).

    Returns:
        A dict serializable to JSON via :func:`json.dumps`. The returned
        object is fresh on every call; callers may mutate it freely.
    """
    paths: dict[str, Any] = {}
    paths.update(_path_devices())
    paths.update(_path_cmdb())
    paths.update(_path_vault())
    paths.update(_path_auth_misc())
    paths.update(_path_virt())
    paths.update(_path_ingest())
    paths.update(_path_identity())
    _stub_operations(paths, routes)

    return {
        "openapi": "3.1.0",
        "info": {
            "title": "RemotePower API",
            "version": server_version,
            "description": (
                "Self-hosted dashboard for remotely managing Linux/Windows "
                "machines. All endpoints are rooted at ``/api`` — the paths "
                "in this document are relative to that prefix.\n\n"
                "**Authentication.** Most endpoints require an "
                "``X-Token`` header containing either a session token "
                "(from ``POST /login``) or a long-lived API key. The "
                "vault credential endpoints additionally require an "
                "``X-RP-Vault-Key`` header carrying the AES-GCM key "
                "derived from the vault passphrase.\n\n"
                "**Rate limits.** Login is rate-limited per source IP. "
                "Other endpoints are not currently rate-limited.\n\n"
                "**Audit logging.** Every mutating endpoint records an "
                "entry in the audit log with the actor, action, and "
                "(where applicable) the source IP."
            ),
        },
        "servers": [
            {"url": "/api/v1", "description": "Versioned base (recommended)."},
            {"url": "/api", "description": "Unversioned alias of /api/v1."},
        ],
        "tags": [
            {"name": "Auth", "description": "Login, logout, audit log."},
            {"name": "Devices", "description": "Enrolled device CRUD and inspection."},
            {"name": "Commands", "description": "Queue commands for one or more devices."},
            {"name": "CMDB", "description": "Per-asset metadata and documentation."},
            {"name": "Vault", "description": "Encrypted credential vault (PBKDF2 + AES-GCM)."},
            {"name": "Credentials", "description": "Per-asset credential storage."},
            {"name": "Reporting", "description": "Metrics and read-only reports."},
            {"name": "Other", "description": "Endpoints not yet richly documented (auto-stubbed)."},
        ],
        "paths": paths,
        "components": {
            "schemas": _schemas(),
            "responses": _common_responses(),
            "requestBodies": _common_request_bodies(),
            "securitySchemes": _security_schemes(),
        },
        "security": [{"SessionToken": []}, {"ApiKey": []}],
    }
