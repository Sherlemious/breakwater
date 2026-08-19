FROM node:20-slim AS frontend-builder

WORKDIR /app/dashboard/frontend
COPY dashboard/frontend/package.json ./package.json
RUN npm install
COPY dashboard/frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SQLITE_DB_PATH=/app/db/ddos_tool.db \
    BACKEND_PORT=8050 \
    FRONTEND_DIST=/app/dashboard/frontend/dist

WORKDIR /app

COPY dashboard/backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY dashboard/backend/ /app/dashboard/backend/
COPY ingestion/ /app/ingestion/
COPY model/ /app/model/
COPY --from=frontend-builder /app/dashboard/frontend/dist /app/dashboard/frontend/dist

EXPOSE 8050

CMD ["python", "/app/dashboard/backend/app.py"]
