"""MS Graph authentication and client setup."""

from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient


def create_graph_client(
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> GraphServiceClient:
    """Create an authenticated MS Graph client."""
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )

    return GraphServiceClient(credentials=credential)
