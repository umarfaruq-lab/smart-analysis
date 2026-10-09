from fastapi import FastAPI, Depends, HTTPException, Security, Request, status 
from fastapi.responses import FileResponse
@app.get("/") 
async def serve\_frontend():
    """Serves the Umarmathi Trading Dashboard""" 
return FileResponse("index.html")
@app.get("/")
@app.get("/health")
@app.get("/healthz")
async def health\_check():
    """Liveness probe for Render and Uptime monitoring"""
return { 
  "status": "healthy", "service": "Umarmathi Pivot Engine" }
