import os
import time
import requests
from dotenv import load_dotenv
from sqlalchemy import func
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE
from dnslib.server import DNSServer, BaseResolver
from . import models
from . import database
load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
CANARY_SUFFIX = ".canary.twc4n.com"
ANSWER_IP = "178.128.154.79"
def send_discord_alert(message: str):
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"Failed to send Discord alert: {e}")
class CanaryResolver(BaseResolver):
    def resolve(self, request, handler):
        queried_name = str(request.q.qname).rstrip(".")
        print(f"DNS query received for: {queried_name}")
        if queried_name.lower().endswith(CANARY_SUFFIX.lower()):
            token_id = queried_name[: -len(CANARY_SUFFIX)]
            self._handle_canary_query(token_id, handler)
        reply = request.reply()
        reply.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=60,
                rdata=A(ANSWER_IP),
            )
        )
        return reply
    def _handle_canary_query(self, token_id: str, handler):
        db = database.SessionLocal()
        try:
            token = (
                db.query(models.Tokens)
                .filter(func.lower(models.Tokens.token_id) == token_id.lower())
                .first()
            )
            if token and token.token_type == "dns":
                source_ip = handler.client_address[0]
                trigger = models.Triggers(
                    token_reference=token.id,
                    source_ip=source_ip,
                    user_agent="dns-query",
                )
                db.add(trigger)
                db.commit()
                db.refresh(trigger)
                send_discord_alert(
                    f"🚨 DNS Canary Triggered 🚨\n"
                    f"-------------------------------\n"
                    f"Canary Name: {token.token_name}\n"
                    f"Canary ID: {token.token_id}\n"
                    f"Source IP: {source_ip}"
                )
        finally:
            db.close()
if __name__ == "__main__":
    resolver = CanaryResolver()
    server = DNSServer(resolver, port=53, address="0.0.0.0")
    print("DNS canary listener starting on port 53...")
    server.start_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down DNS canary listener.")
        server.stop()