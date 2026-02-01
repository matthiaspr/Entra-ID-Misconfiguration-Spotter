"""MS Graph authentication and client setup."""

import asyncio
from typing import Coroutine, TypeVar

from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient

T = TypeVar("T")


def run_sync(coro: Coroutine[None, None, T]) -> T:
    """Run an async coroutine synchronously.

    This allows us to use the async msgraph-sdk in a sync context.
    """
    return asyncio.run(coro)


def create_graph_client(
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> GraphServiceClient:
    """Create an authenticated MS Graph client.

    Args:
        tenant_id: Azure tenant ID
        client_id: Service principal client ID
        client_secret: Service principal client secret

    Returns:
        Authenticated GraphServiceClient
    """
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )

    return GraphServiceClient(credentials=credential)
