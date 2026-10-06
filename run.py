from app.main import create_app
import uvicorn

app = create_app()

if __name__ == "__main__":
    from app.config import load_config

    cfg = load_config()
    uvicorn.run(app, host=cfg.host, port=cfg.port)
