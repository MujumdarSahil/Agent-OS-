# AgentOS UI Setup

## Status

✅ **Backend Server**: Running on http://localhost:8000
✅ **Frontend Server**: Starting on http://localhost:3000

## Services Running

### 1. FastAPI Backend
- **Location**: `agentos/ui/backend/`
- **Port**: 8000
- **Command**: `uvicorn main:app --host localhost --port 8000 --reload`
- **Status**: Running in background
- **API Endpoints**:
  - `GET /` - Root endpoint
  - `GET /api/models` - List models
  - `GET /api/tools` - List tools and MCPs
  - `POST /api/tools/{tool_id}/invoke` - Invoke a tool
  - `GET /api/training/jobs` - List training jobs
  - `POST /api/training/sft` - Start SFT training
  - `POST /api/training/lora` - Start LoRA training
  - `GET /api/missions` - List missions
  - `GET /api/governance/policies` - List governance policies

### 2. React Frontend
- **Location**: `agentos/ui/frontend/`
- **Port**: 3000 (default Vite port)
- **Command**: `npm run dev`
- **Status**: Starting in background
- **URL**: http://localhost:3000

## Frontend Pages

The UI includes the following tabs:
1. **Models** - View and manage LLM models
2. **Training** - Monitor training jobs (SFT, LoRA, QLoRA)
3. **Tools & MCPs** - Browse and invoke MCP tools
4. **Missions** - View and manage agent missions
5. **Safety** - Monitor governance and safety policies

## Accessing the UI

1. Open your browser and navigate to: **http://localhost:3000**
2. The frontend will automatically connect to the backend at http://localhost:8000
3. You may need to set an API token (stored in localStorage)

## Files Created

The following files were created to set up the frontend:
- `index.html` - HTML entry point
- `vite.config.js` - Vite configuration
- `src/main.jsx` - React entry point
- `src/index.css` - Tailwind CSS styles
- `tailwind.config.js` - Tailwind configuration
- `postcss.config.js` - PostCSS configuration

## Troubleshooting

### Backend not responding
```bash
cd agentos/ui/backend
python -m uvicorn main:app --host localhost --port 8000 --reload
```

### Frontend not starting
```bash
cd agentos/ui/frontend
npm install
npm run dev
```

### Check if ports are in use
- Backend: `netstat -ano | findstr :8000`
- Frontend: `netstat -ano | findstr :3000`

## Next Steps

1. Open http://localhost:3000 in your browser
2. Check the browser console for any errors
3. Verify the backend is responding at http://localhost:8000
4. Test the API endpoints using the UI or curl/Postman
