"""`request` here is an outgoing HTTP request the service itself built."""
import requests


def send_signed(request, session=None):
    session = session or requests.Session()
    return session.get(request.url, headers=request.headers, timeout=5)
