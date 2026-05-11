from ai.copilot import process_soc_query


async def ask_copilot(
    query: str,
    organization_id: str,
) -> dict:
    return await process_soc_query(query, organization_id)
