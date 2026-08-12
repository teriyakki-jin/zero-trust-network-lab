from fastapi import FastAPI, Request


app = FastAPI(title="Protected Application", docs_url=None, redoc_url=None)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def protected_resource(request: Request, path: str) -> dict[str, str]:
    return {
        "message": "제로 트러스트 정책이 허용한 보호 자원입니다.",
        "user": request.headers.get("x-zt-user", "unknown"),
        "subject": request.headers.get("x-zt-sub", "unknown"),
        "request_id": request.headers.get("x-zt-request-id", "unknown"),
        "path": f"/{path}",
    }
