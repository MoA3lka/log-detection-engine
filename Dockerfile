# Small official Python image
FROM python:3.12-slim

# Don't write .pyc files, and print output straight away
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first, so Docker can reuse this layer when only code changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the tool and its rule files (not tests or sample data)
COPY detector/ detector/
COPY rules/ rules/

# Run as a normal user, not root
RUN useradd --create-home appuser
USER appuser

# Running the container runs the tool; arguments are passed straight to it
ENTRYPOINT ["python", "-m", "detector"]
CMD ["--help"]