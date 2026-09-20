import json
from datetime import timedelta
import logging
from typing import List
from sqlalchemy.orm import Session
from app.models import Event, Incident

log = logging.getLogger("correlation")

# Time window to group events into a single incident.
# If events from the same IP happen within 5 minutes of each other, they are the same incident.
INCIDENT_TIMEOUT_SECONDS = 300

# Mapping rule types to MITRE ATT&CK kill chain stages
KILL_CHAIN_MAPPING = {
    "brute_force": "Credential Access",
    "dos": "Impact",
    "none": "Unknown (ML Anomaly)"
}

def build_entity_graph(events: List[Event]) -> dict:
    """Builds an in-memory graph to calculate blast radius."""
    unique_endpoints = set()
    for ev in events:
        if ev.endpoint:
            unique_endpoints.add(ev.endpoint)
    
    # Blast radius is the number of distinct endpoints hit.
    blast_radius = len(unique_endpoints)
    return {"blast_radius": blast_radius}

def correlate_events(session: Session) -> int:
    """Scan for unassigned events and group them into Incidents."""
    unassigned_events = session.query(Event).filter(Event.incident_id.is_(None)).order_by(Event.ts.asc()).all()
    
    if not unassigned_events:
        return 0
        
    events_by_ip = {}
    for ev in unassigned_events:
        events_by_ip.setdefault(ev.ip, []).append(ev)
        
    incidents_updated_or_created = 0
    
    for ip, events in events_by_ip.items():
        # Find the most recent incident for this IP
        recent_incident = session.query(Incident).filter(
            Incident.patient_zero == ip
        ).order_by(Incident.end_ts.desc()).first()
        
        current_incident_events = []
        
        for ev in events:
            # If we have a recent incident, check if this event belongs to it
            if recent_incident and (ev.ts - recent_incident.end_ts).total_seconds() <= INCIDENT_TIMEOUT_SECONDS:
                ev.incident_id = recent_incident.id
                recent_incident.end_ts = max(recent_incident.end_ts, ev.ts)
                
                # Update kill chain
                try:
                    stages = set(json.loads(recent_incident.kill_chain))
                except (json.JSONDecodeError, TypeError):
                    stages = set()
                stage = KILL_CHAIN_MAPPING.get(ev.rule_type or "none", "Unknown")
                stages.add(stage)
                recent_incident.kill_chain = json.dumps(sorted(stages))
                
                # We need all events for this incident to recalculate blast radius
                all_incident_events = session.query(Event).filter(Event.incident_id == recent_incident.id).all()
                all_incident_events.append(ev)
                graph_metrics = build_entity_graph(all_incident_events)
                recent_incident.blast_radius = graph_metrics["blast_radius"]
                
                session.add(recent_incident)
                incidents_updated_or_created += 1
            else:
                # Group logic for events that start a NEW incident
                if not current_incident_events:
                    current_incident_events.append(ev)
                    continue
                    
                last_ev = current_incident_events[-1]
                time_diff = (ev.ts - last_ev.ts).total_seconds()
                
                if time_diff <= INCIDENT_TIMEOUT_SECONDS:
                    current_incident_events.append(ev)
                else:
                    _create_incident(session, ip, current_incident_events)
                    incidents_updated_or_created += 1
                    current_incident_events = [ev]
                    recent_incident = None # Reset so next batch can attach to the new one if needed
                    
        # Close out remaining new incident
        if current_incident_events:
            _create_incident(session, ip, current_incident_events)
            incidents_updated_or_created += 1
            
    return incidents_updated_or_created

def _create_incident(session: Session, ip: str, events: List[Event]) -> None:
    start_ts = events[0].ts
    end_ts = events[-1].ts
    
    graph_metrics = build_entity_graph(events)
    
    # Map rules to kill chain
    stages = set()
    for ev in events:
        stage = KILL_CHAIN_MAPPING.get(ev.rule_type or "none", "Unknown")
        stages.add(stage)
        
    incident = Incident(
        start_ts=start_ts,
        end_ts=end_ts,
        patient_zero=ip,
        blast_radius=graph_metrics["blast_radius"],
        kill_chain=json.dumps(list(stages))
    )
    
    session.add(incident)
    session.flush() # get the incident ID
    
    # Assign incident ID to all events
    for ev in events:
        ev.incident_id = incident.id
        
    log.info(f"Created Incident {incident.id} for IP {ip} with {len(events)} events. Blast Radius: {incident.blast_radius}")
