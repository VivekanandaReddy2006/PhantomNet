import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from database.database import get_db
from sentinel.models import SentinelPlaybook

router = APIRouter()

@router.get("/taxii2/", summary="TAXII 2.1 Discovery")
async def taxii_discovery():
    """
    Returns the TAXII 2.1 discovery document containing system-wide api_roots.
    """
    discovery_data = {
        "title": "PhantomNet TAXII 2.1 Server",
        "description": "System-wide TAXII 2.1 discovery document",
        "contact": "admin@phantomnet.local",
        "default": "https://phantomnet.local/taxii2/api1/",
        "api_roots": [
            "https://phantomnet.local/taxii2/api1/"
        ]
    }
    return JSONResponse(
        content=discovery_data,
        media_type="application/taxii+json;version=2.1"
    )

@router.get("/taxii2/phantomnet/collections/{id}/objects/", summary="Get TAXII Collection Objects")
async def get_collection_objects(
    id: str = Path(..., description="The ID of the collection"),
    db: Session = Depends(get_db)
):
    """
    Returns a STIX 2.1 bundle containing objects for the requested collection.
    Queries SentinelPlaybook to map threats into STIX format.
    """
    if not id or id.strip() == "":
        raise HTTPException(status_code=400, detail="Collection ID cannot be empty.")
    
    # We simulate serving objects from 'phantomnet' collection. 
    # For a real implementation, we would verify the collection id exists.
    try:
        playbooks = db.query(SentinelPlaybook).all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    stix_objects = []
    for pb in playbooks:
        # Determine valid timestamps in STIX format (append Z for UTC)
        created_at = pb.created_at.isoformat() + "Z" if pb.created_at else datetime.utcnow().isoformat() + "Z"
        updated_at = pb.updated_at.isoformat() + "Z" if pb.updated_at else created_at
        
        # We can map each playbook to a STIX 'report'
        report_id = f"report--{pb.playbook_id if pb.playbook_id else uuid.uuid4()}"
        report_obj = {
            "type": "report",
            "id": report_id,
            "name": pb.playbook_name or "Generated Threat Playbook",
            "description": pb.playbook_content or "No content available",
            "published": created_at,
            "created": created_at,
            "modified": updated_at,
            "object_refs": []
        }
        stix_objects.append(report_obj)
        
        # If there's an attacker IP, add an indicator and reference it in the report
        if pb.src_ip:
            indicator_id = f"indicator--{uuid.uuid4()}"
            indicator_obj = {
                "type": "indicator",
                "id": indicator_id,
                "name": f"Malicious Source IP: {pb.src_ip}",
                "pattern": f"[ipv4-addr:value = '{pb.src_ip}']",
                "pattern_type": "stix",
                "valid_from": created_at,
                "created": created_at,
                "modified": updated_at
            }
            stix_objects.append(indicator_obj)
            report_obj["object_refs"].append(indicator_id)
            
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects
    }
    
    return JSONResponse(
        content=bundle,
        media_type="application/taxii+json;version=2.1"
    )
