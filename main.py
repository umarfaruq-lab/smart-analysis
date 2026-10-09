from fastapi import FastAPI, Depends, HTTPException, Security, Request, status 
from fastapi.responses import FileResponse 
... (middleware setup remains the same) ... 
@app.get("/") 
async def serve\_frontend():
"""Serves the Umarmathi Trading Dashboard""" 
return FileResponse("index.html") 
@app.get("/health")
@app.get("/healthz")
async def health\_check():
"""Liveness probe for Render and Uptime monitoring""" 
return { "status": "healthy", "service": "Umarmathi Pivot Engine" }
