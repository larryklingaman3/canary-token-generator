from fastapi import FastAPI, Depends, Request, Response, Form
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from pydantic import BaseModel
import os
import requests
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from . import models
from . import database
from . import url_token

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
def send_discord_alert(message: str):
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"Failed to send a discord web alert: {e}")



database.Base.metadata.create_all(bind=database.engine)
app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

class CreateTokenRequest(BaseModel):
    token_name: str

@app.get("/health")
def health_check():
    return {"status": "OK!"}

@app.post("/url_token")
def create_url_token(payload: CreateTokenRequest, request:Request, db: Session = Depends(database.get_db)):
    token_id = url_token.generate_token_id()
    new_token = models.Tokens(token_id=token_id, token_name=payload.token_name, token_type="url")
    db.add(new_token)
    db.commit()
    db.refresh(new_token)
    return new_token

@app.get("/{token_id}")
@limiter.limit("5/second")
def url_trigger(token_id: str, request:Request, db: Session = Depends(database.get_db)):
    token = db.query(models.Tokens).filter(models.Tokens.token_id == token_id).first()
    if token and token.token_type == "url":
        trigger = models.Triggers(token_reference=token.id, user_agent=request.headers.get('User-Agent'), source_ip=request.client.host)
        db.add(trigger)
        db.commit()
        db.refresh(trigger)
        send_discord_alert(f"🚨 URL Canary Triggered 🚨\n-------------------------------\nCanary Name: {token.token_name}\nCanary ID: {token.token_id}\nSource IP: {trigger.source_ip}\nUser-Agent: {trigger.user_agent}")
    return Response(content=url_token.TRANSPARENT_PIXEL, media_type="image/png")


@app.post("/url_token")
def create_url_token(payload: CreateTokenRequest, request: Request, db: Session = Depends(database.get_db)):
    token_id = url_token.generate_token_id()
    new_token = models.Tokens(token_id=token_id, token_name=payload.token_name, token_type="url")
    db.add(new_token)
    db.commit()
    db.refresh(new_token)
    return new_token

@app.post("/dns_token")
def create_dns_token(payload: CreateTokenRequest, request: Request, db: Session = Depends(database.get_db)):
    token_id = url_token.generate_token_id()
    new_token = models.Tokens(token_id=token_id, token_name=payload.token_name, token_type="dns")
    db.add(new_token)
    db.commit()
    db.refresh(new_token)
    return new_token
