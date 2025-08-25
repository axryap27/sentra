from fastapi import FastAPI, UploadFile, File
from backend.ai_engine import analyze_code_with_ai
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev only – restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


#landing endpoint per se
@app.get("/")
def read_root():
    return {"message": "AI Code Security Assistant is running."}

#endpoint to check api functionality
@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()
    result = analyze_code_with_ai(content.decode())
    return {"result": result}
