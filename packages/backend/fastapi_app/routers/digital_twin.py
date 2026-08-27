from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

class TwinResponse(BaseModel):
    id: str
    project_id: str
    name: str
    status: str
    environment: dict
    created_at: str

class ScenarioCreate(BaseModel):
    name: str
    change_type: str
    description: str = ""
    affected_nodes: List[str]
    parameters: dict = {}

class ScenarioResponse(BaseModel):
    id: str
    twin_id: str
    name: str
    change_type: str
    description: str
    affected_nodes: List[str]
    security_impact: float
    performance_impact: float
    risk_reduction: float
    recommendation: str
    status: str
    created_at: str

class SimulationRequest(BaseModel):
    scenario_id: str

@router.get("/projects/{project_id}/twins", response_model=List[TwinResponse])
async def list_twins(project_id: str):
    return []

@router.post("/projects/{project_id}/twins", response_model=TwinResponse)
async def create_twin(project_id: str, name: str, assets: List[dict]):
    return TwinResponse(
        id="new-twin-id",
        project_id=project_id,
        name=name,
        status="building",
        environment={},
        created_at=datetime.utcnow().isoformat(),
    )

@router.get("/twins/{twin_id}", response_model=TwinResponse)
async def get_twin(twin_id: str):
    raise HTTPException(status_code=404, detail="Digital Twin not found")

@router.post("/twins/{twin_id}/build")
async def build_twin(twin_id: str):
    return {"message": "Twin build started", "status": "building"}

@router.get("/twins/{twin_id}/scenarios", response_model=List[ScenarioResponse])
async def list_scenarios(twin_id: str):
    return []

@router.post("/twins/{twin_id}/scenarios", response_model=ScenarioResponse)
async def create_scenario(twin_id: str, scenario: ScenarioCreate):
    return ScenarioResponse(
        id="new-scenario-id",
        twin_id=twin_id,
        name=scenario.name,
        change_type=scenario.change_type,
        description=scenario.description,
        affected_nodes=scenario.affected_nodes,
        security_impact=0,
        performance_impact=0,
        risk_reduction=0,
        recommendation="",
        status="pending",
        created_at=datetime.utcnow().isoformat(),
    )

@router.post("/scenarios/{scenario_id}/simulate", response_model=ScenarioResponse)
async def simulate_scenario(scenario_id: str):
    # TODO: Run simulation
    return ScenarioResponse(
        id=scenario_id,
        twin_id="twin-id",
        name="Simulated Scenario",
        change_type="config_change",
        description="",
        affected_nodes=[],
        security_impact=2.5,
        performance_impact=0.5,
        risk_reduction=15.0,
        recommendation="Recommended - reduces risk",
        status="completed",
        created_at=datetime.utcnow().isoformat(),
    )

@router.post("/twins/{twin_id}/drift-check")
async def check_drift(twin_id: str, current_assets: List[dict]):
    return {
        "drift": 0,
        "missing_in_model": [],
        "extra_in_model": [],
        "status": "ready",
    }