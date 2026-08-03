const { spawn } = require('child_process');
const PYTHON_PORT = process.env.PORT || 8001;

// Spawn Python with inherited environment variables including DATABASE_URL
const pythonProcess = spawn('uvicorn', ['main:app', '--host', '127.0.0.1', '--port', PYTHON_PORT.toString()], {
  stdio: ['inherit', 'inherit', 'pipe'], // Capture stderr separately for debugging
  shell: true,
  env: { ...process.env, PYTHONUNBUFFERED: "true" }
});

pythonProcess.stderr.on('data', (data) => {
  console.error(`[FastAPI Error]: ${data.toString()}`);
});

pythonProcess.on('exit', (code, signal) => {
  console.error(`[FastAPI Process exited with code ${code} and signal ${signal}]`);
  // Optional: Trigger an automatic restart or gracefully shut down Node
});
```[cite: 10]

---

### Step 3: Enforce Robust Database Initialization
FastAPI crashes on startup usually stem from unhandled database exceptions during table creation. Wrap your database engine initialization inside a safe try-except block in `main.py` to prevent the app from dying before Uvicorn can bind to the port:

```python
import os
from sqlmodel import SQLModel, create_engine

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./socia_database.db")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

try:
    engine = create_engine(DATABASE_URL, echo=True)
    def init_db():
        SQLModel.metadata.create_all(engine)
except Exception as e:
    print(f"Database initialization warning: {e}")