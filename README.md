[README.md](https://github.com/user-attachments/files/29332937/README.md)
# AI-Powered SOC Analyst Assistant

An interactive, real-time Security Operations Center (SOC) analyst assistant. It triages security alerts, maps threat scenarios to the MITRE ATT&CK framework, explains attack mechanisms, suggests mitigation playbooks, and allows direct operator chat.

## 🛠️ Tech Stack
- **Backend**: Python, FastAPI, Uvicorn, LangChain
- **Frontend**: HTML5, Vanilla CSS, JavaScript
- **Models**: Local Ollama (llama3) & API-based Cloud Models (OpenAI, Anthropic, Gemini)

## 📂 Structure
- `backend/`: Server APIs, MITRE engine, log simulators, and LLM prompting.
- `frontend/`: Dashboard interface, CSS styles, and state management JS.

## 🚀 Setup & Execution

1. **Activate virtual environment**:
   ```bash
   cd ai-soc-analyst
   source venv/bin/activate
   ```
2. **Start the server**:
   ```bash
   uvicorn backend.main:app --host 0.0.0.0 --port 8000
   ```
3. **Access**:
   Open browser at [http://localhost:8000](http://localhost:8000).
   Use the **Config** button to toggle between local Ollama or cloud API models.
