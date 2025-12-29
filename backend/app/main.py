from fastapi import FastAPI, Depends, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List, Optional
import uvicorn
import os

# Import application modules
from app.config import settings
from app.database import engine, get_db
from app import models, schemas
from app.ingestion.nginx import parse_nginx_log
from app.analysis.endpoint_frequency import analyze_endpoint_abuse
from app.analysis.ip_ranking import analyze_ip_behavior
from app.utils.risk import calculate_risk_score

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(title="ForenX-Sentinel", version="1.0.0")

# Mount static files for dashboard (basic frontend)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the main dashboard interface."""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ForenX-Sentinel Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .card { border: 1px solid #ccc; padding: 20px; margin: 10px; border-radius: 5px; }
            .high-risk { border-left: 5px solid #dc3545; }
            .medium-risk { border-left: 5px solid #ffc107; }
            .low-risk { border-left: 5px solid #28a745; }
        </style>
    </head>
    <body>
        <h1>🕵️ ForenX-Sentinel</h1>
        <p>Digital Forensics & Incident Response Engine</p>
        
        <div class="card">
            <h3>📊 System Status</h3>
            <p>Backend API is operational. Use the endpoints below:</p>
            <ul>
                <li><strong>POST /api/upload/</strong> - Upload log files for analysis</li>
                <li><strong>GET /api/stats/</strong> - Get analysis statistics</li>
                <li><strong>GET /api/endpoints/</strong> - View endpoint risk analysis</li>
                <li><strong>GET /api/ips/</strong> - View IP threat intelligence</li>
            </ul>
        </div>
        
        <div class="card">
            <h3>🚀 Quick Start</h3>
            <p>Upload your first log file using curl:</p>
            <code>curl -X POST -F "file=@access.log" http://localhost:8000/api/upload/</code>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/api/upload/", response_model=schemas.UploadResponse)
async def upload_log_file(
    file: UploadFile = File(...),
    log_type: str = "nginx",
    db: Session = Depends(get_db)
):
    """
    Forensic log ingestion endpoint.
    Accepts log files, parses them according to type, and stores normalized events.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Read file content
    content = await file.read()
    log_lines = content.decode('utf-8').splitlines()
    
    # Parse based on log type
    parsed_events = []
    if log_type == "nginx":
        parsed_events = parse_nginx_log(log_lines)
    else:
        # Default: treat as generic web log
        parsed_events = parse_nginx_log(log_lines)
    
    # Store events in database
    for event_data in parsed_events:
        db_event = models.LogEvent(**event_data)
        db.add(db_event)
    
    db.commit()
    
    return {
        "filename": file.filename,
        "log_type": log_type,
        "events_ingested": len(parsed_events),
        "message": "Log file ingested successfully. Analysis available."
    }

@app.get("/api/stats/", response_model=schemas.SystemStats)
async def get_system_stats(db: Session = Depends(get_db)):
    """Get overall system statistics and metrics."""
    from sqlalchemy import func, distinct
    
    total_events = db.query(func.count(models.LogEvent.id)).scalar() or 0
    unique_ips = db.query(func.count(distinct(models.LogEvent.ip))).scalar() or 0
    unique_endpoints = db.query(func.count(distinct(models.LogEvent.endpoint))).scalar() or 0
    
    # Calculate total data volume
    total_volume = db.query(func.sum(models.LogEvent.response_size)).scalar() or 0
    
    return {
        "total_events": total_events,
        "unique_ips": unique_ips,
        "unique_endpoints": unique_endpoints,
        "total_data_volume": total_volume,
        "analysis_timestamp": "2025-12-30T10:00:00Z"
    }

@app.get("/api/endpoints/", response_model=List[schemas.EndpointAnalysis])
async def get_endpoint_analysis(
    limit: int = 10,
    min_hits: int = 1,
    db: Session = Depends(get_db)
):
    """
    Get abused endpoint ranking by frequency and data volume.
    Supports pagination via limit parameter.
    """
    return analyze_endpoint_abuse(db, limit, min_hits)

@app.get("/api/ips/", response_model=List[schemas.IPAnalysis])
async def get_ip_analysis(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Get malicious IP rankings with behavior patterns.
    """
    return analyze_ip_behavior(db, limit)

# Application entry point
if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
