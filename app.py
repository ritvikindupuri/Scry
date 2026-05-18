"""
Scry - Reveal Hidden Threats
"""

from flask import Flask, render_template, Response, request, jsonify, send_file
from flask_cors import CORS
import json
import os
import threading
import queue
import time
from datetime import datetime
from pathlib import Path
app = Flask(__name__)
CORS(app)

PROGRESS_QUEUE = queue.Queue()
SESSION_DATA = {
    "telemetry": None,
    "command_logs": [],
    "prompts": {},
    "agent_outputs": {"agent1": "", "agent2": "", "agent3": ""},
    "model": None,
    "status": "idle"
}
IS_RUNNING = False


def run_analysis():
    """Main analysis pipeline with full logging"""
    global IS_RUNNING, SESSION_DATA
    
    def emit_event(event_type: str, data: dict):
        PROGRESS_QUEUE.put({"type": event_type, **data, "timestamp": datetime.now().isoformat()})
    
    try:
        from dotenv import load_dotenv
        from agents.chain import run_claude_chain
        
        load_dotenv()
        IS_RUNNING = True
        SESSION_DATA = {
            "telemetry": None,
            "command_logs": [],
            "prompts": {},
            "agent_outputs": {"agent1": "", "agent2": "", "agent3": ""},
            "model": None,
            "status": "running"
        }
        
        # Step 1: Telemetry Collection
        emit_event("phase", {"phase": "telemetry", "status": "starting", "message": "Initializing telemetry collector..."})
        
        from collectors.enhanced_metrics import LoggingCollector
        
        def on_command(cmd_log):
            SESSION_DATA["command_logs"].append(cmd_log)
            emit_event("command", {
                "command": cmd_log.command,
                "category": cmd_log.category,
                "description": cmd_log.description,
                "status": cmd_log.status,
                "output": cmd_log.output[:1500] if cmd_log.output else "",
                "error": cmd_log.error[:500] if cmd_log.error else "",
                "duration_ms": cmd_log.duration_ms
            })
        
        collector = LoggingCollector(on_command_update=on_command)
        
        emit_event("phase", {"phase": "telemetry", "status": "running", "message": "Collecting system metrics..."})
        
        snapshot = collector.collect_full_telemetry()
        session_summary = collector.get_session_summary()
        
        SESSION_DATA["telemetry"] = snapshot
        SESSION_DATA["command_logs"] = session_summary["commands"]
        
        emit_event("phase", {"phase": "telemetry", "status": "complete", 
            "message": f"Telemetry collected! {session_summary['successful_commands']} commands executed successfully"})
        
        # Step 2-4: Agent Chain
        model = os.environ.get("OPENROUTER_MODEL", "deepseek/deepseek-chat-v3")
        SESSION_DATA["model"] = model
        
        last_agent = "agent1"
        
        def on_agent_chunk(agent_id: str, chunk: str):
            nonlocal last_agent
            if agent_id != last_agent:
                last_agent = agent_id
                if agent_id == "agent2":
                    emit_event("phase", {"phase": "agent2", "status": "starting", "message": "Threats agent analyzing attack surface..."})
                elif agent_id == "agent3":
                    emit_event("phase", {"phase": "agent3", "status": "starting", "message": "Scenarios agent generating MITRE scenarios..."})
            SESSION_DATA["agent_outputs"][agent_id] += chunk
            emit_event("agent_chunk", {
                "agent": agent_id,
                "chunk": chunk,
                "full_output": SESSION_DATA["agent_outputs"][agent_id]
            })
        
        # Load actual prompts from files
        prompts_dir = Path(__file__).parent / "agents" / "prompts"
        prompts = {
            "agent1": (prompts_dir / "agent1_facts.txt").read_text(encoding="utf-8").strip(),
            "agent2": (prompts_dir / "agent2_attack_surface.txt").read_text(encoding="utf-8").strip(),
            "agent3": (prompts_dir / "agent3_scenario.txt").read_text(encoding="utf-8").strip(),
        }
        SESSION_DATA["prompts"] = prompts
        
        # Emit each prompt to the command log
        emit_event("prompt", {
            "agent": "agent1",
            "name": "Observations",
            "prompt": prompts["agent1"]
        })
        emit_event("prompt", {
            "agent": "agent2", 
            "name": "Threats",
            "prompt": prompts["agent2"]
        })
        emit_event("prompt", {
            "agent": "agent3",
            "name": "Scenarios",
            "prompt": prompts["agent3"]
        })
        
        # Run the agent chain
        emit_event("phase", {"phase": "agent1", "status": "starting", "message": "Agent 1 analyzing telemetry..."})
        
        result = run_claude_chain(
            snapshot, 
            stream=True,
            on_agent_chunk=on_agent_chunk
        )
        
        SESSION_DATA["agent_outputs"]["agent1"] = result.agent1_facts
        SESSION_DATA["agent_outputs"]["agent2"] = result.agent2_mapping
        SESSION_DATA["agent_outputs"]["agent3"] = result.agent3_scenario
        SESSION_DATA["model"] = result.model
        SESSION_DATA["status"] = "complete"
        
        emit_event("phase", {"phase": "complete", "status": "complete", 
            "message": f"Analysis complete! Model: {result.model}"})
        
        IS_RUNNING = False
        
    except Exception as e:
        import traceback
        emit_event("error", {"message": str(e), "trace": traceback.format_exc()})
        IS_RUNNING = False
        SESSION_DATA["status"] = "error"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({
        "running": IS_RUNNING,
        "status": SESSION_DATA.get("status", "idle"),
        "has_data": SESSION_DATA.get("telemetry") is not None
    })


@app.route("/api/execute", methods=["POST"])
def execute():
    global IS_RUNNING
    
    if IS_RUNNING:
        return jsonify({"error": "Analysis already running"}), 400
    
    PROGRESS_QUEUE.queue.clear()
    
    thread = threading.Thread(target=run_analysis)
    thread.daemon = True
    thread.start()
    
    return jsonify({"message": "Analysis started"})


@app.route("/api/stream")
def stream():
    def generate():
        while True:
            try:
                item = PROGRESS_QUEUE.get(timeout=60)
                yield f"data: {json.dumps(item, default=str)}\n\n"
                
                # Small delay for agent chunks to moderate streaming speed
                if item.get("type") == "agent_chunk":
                    time.sleep(0.02)  # 20ms delay between chunks
                
                if item.get("type") == "complete" or item.get("type") == "error":
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': datetime.now().isoformat()})}\n\n"
    
    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/telemetry")
def get_telemetry():
    if SESSION_DATA.get("telemetry") is None:
        return jsonify({"error": "No telemetry available"}), 400
    return jsonify(SESSION_DATA["telemetry"])


@app.route("/api/commands")
def get_commands():
    return jsonify({
        "commands": SESSION_DATA.get("command_logs", []),
        "total": len(SESSION_DATA.get("command_logs", []))
    })


@app.route("/api/prompts")
def get_prompts():
    return jsonify(SESSION_DATA.get("prompts", {}))


@app.route("/api/agents")
def get_agents():
    return jsonify({
        "agent1": SESSION_DATA["agent_outputs"].get("agent1", ""),
        "agent2": SESSION_DATA["agent_outputs"].get("agent2", ""),
        "agent3": SESSION_DATA["agent_outputs"].get("agent3", "")
    })


if __name__ == "__main__":
    app.run(debug=True, threaded=True, port=5000, host='0.0.0.0')
