from fastapi.responses import FileResponse
@app.get("/")
async def serve\_frontend():
    """Serves the main TradingView dashboard interface""" 
    return FileResponse("index.html")
