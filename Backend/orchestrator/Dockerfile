FROM python:3.10-slim

WORKDIR /app

COPY orchestrator/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt


COPY models/ ./models/

COPY agents/common/ ./agents/common/

COPY auth/ ./auth/

COPY orchestrator/app/ ./app/

ENV PYTHONPATH=/app

# Expose the port your application will listen on
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]