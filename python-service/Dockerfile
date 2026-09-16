# See rust-core/Dockerfile's note: not built/tested in this session
# (no Docker daemon available in the development sandbox).
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
ENV IOD_PYTHON_PORT=5001
ENV IOD_PYTHON_HOST=0.0.0.0
EXPOSE 5001
CMD ["python", "src/app.py"]
