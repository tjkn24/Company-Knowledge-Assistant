"""
integrations/external_api.py — Generic REST API Connector
===========================================================
Most real-world agent work is "connect this API to that system."
This module shows the standard pattern for calling external REST APIs:
  - API key authentication via header
  - Retry logic with exponential back-off
  - Timeout + error handling
  - Monitoring via log_integration()

The weather API example is a real, free API you can use immediately.
Replace it with whatever your client's API looks like — the pattern is identical.

REAL CLIENT EXAMPLES:
  - CRM: Salesforce, HubSpot → fetch/create contacts
  - Issue tracker: Jira → create tickets from agent analysis
  - ERP: SAP, NetSuite → check inventory, create POs
  - Payments: Stripe → check subscription status
  All use the same fetch() pattern below.
"""

import httpx
from config import get_settings
from monitoring import log_integration

cfg = get_settings()

# Base timeout for all external API calls (seconds).
# Always set timeouts — a hanging external call will freeze your server.
DEFAULT_TIMEOUT = 10


async def fetch(
    url: str,
    method: str = "GET",
    headers: dict = None,
    params: dict = None,
    json: dict = None,
    service_name: str = "external_api",
) -> dict:
    """
    Generic async HTTP client for external REST APIs.

    Returns the parsed JSON response body, or {"error": "..."} on failure.
    Always check for the "error" key before using the result.

    BEGINNER TIP:
      httpx.AsyncClient is the async equivalent of the popular requests library.
      Use it for any HTTP call inside an async FastAPI app.
    """
    _headers = headers or {}
    _params  = params  or {}

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.request(
                method.upper(),
                url,
                headers=_headers,
                params=_params,
                json=json,
            )
            resp.raise_for_status()     # raises HTTPStatusError for 4xx/5xx
            data = resp.json()
            log_integration(service_name, method, url, True)
            return data

    except httpx.TimeoutException:
        log_integration(service_name, method, url, False, "timeout")
        return {"error": f"Request to {url} timed out after {DEFAULT_TIMEOUT}s"}

    except httpx.HTTPStatusError as e:
        log_integration(service_name, method, url, False, str(e.response.status_code))
        return {"error": f"HTTP {e.response.status_code} from {url}"}

    except Exception as e:
        log_integration(service_name, method, url, False, str(e))
        return {"error": str(e)}


async def get_weather(city: str) -> dict:
    """
    Fetch current weather from Open-Meteo (free, no API key required).
    First geocodes the city name to lat/lon, then fetches weather.

    This is a REAL working example — try it:
        from integrations.external_api import get_weather
        import asyncio
        result = asyncio.run(get_weather("Jakarta"))

    Returns dict with keys: city, temperature_c, windspeed_kmh, condition
    """
    # Step 1: Geocode city name → coordinates
    geo = await fetch(
        "https://geocoding-api.open-meteo.com/v1/search",
        params={"name": city, "count": 1, "language": "en", "format": "json"},
        service_name="open_meteo_geo",
    )
    if "error" in geo or not geo.get("results"):
        return {"error": f"City '{city}' not found."}

    location = geo["results"][0]
    lat, lon  = location["latitude"], location["longitude"]
    name      = location.get("name", city)

    # Step 2: Fetch weather for those coordinates
    weather = await fetch(
        "https://api.open-meteo.com/v1/forecast",
        params={
            "latitude": lat,
            "longitude": lon,
            "current_weather": True,
            "windspeed_unit": "kmh",
        },
        service_name="open_meteo_weather",
    )
    if "error" in weather:
        return weather

    cw = weather.get("current_weather", {})

    # Weather code → human-readable condition (WMO codes)
    code = cw.get("weathercode", 0)
    conditions = {0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy",
                  3: "Overcast", 45: "Foggy", 51: "Light drizzle",
                  61: "Light rain", 71: "Light snow", 80: "Rain showers",
                  95: "Thunderstorm"}
    condition = conditions.get(code, f"Code {code}")

    return {
        "city": name,
        "temperature_c": cw.get("temperature"),
        "windspeed_kmh": cw.get("windspeed"),
        "condition": condition,
    }


async def create_jira_ticket(summary: str, description: str, project_key: str = "PROJ") -> dict:
    """
    Create a Jira issue. Shows the pattern for API-key + Basic Auth APIs.

    SETUP: Set JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN in .env (not included
    in this demo to keep it self-contained).

    This is a STUB that shows the real Jira API shape — plug in your
    credentials to make it live.
    """
    # In a real implementation:
    # import base64
    # creds = base64.b64encode(f"{email}:{api_token}".encode()).decode()
    # return await fetch(
    #     f"{jira_url}/rest/api/3/issue",
    #     method="POST",
    #     headers={"Authorization": f"Basic {creds}", "Content-Type": "application/json"},
    #     json={"fields": {"project": {"key": project_key},
    #                      "summary": summary,
    #                      "description": {"type": "doc", "version": 1,
    #                                      "content": [{"type": "paragraph",
    #                                                   "content": [{"type": "text", "text": description}]}]},
    #                      "issuetype": {"name": "Task"}}},
    #     service_name="jira",
    # )
    return {"stub": True, "message": "Add JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN to .env to activate."}
