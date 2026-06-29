FROM python:3.11-slim

LABEL maintainer="privacy-pii-redactor contributors"
LABEL description="Privacy-First PII Redactor - OpenAI-compatible proxy with PII detection"

WORKDIR /app

# Create non-root user for security
RUN addgroup --system appgroup && adduser --system --group appuser

# Copy only dependency files first for better Docker layer caching
COPY pyproject.toml .

# Install dependencies (including dev extras for the full feature set)
# Note: spaCy model download happens here during image build
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e ".[dev]" && \
    python -m spacy download en_core_web_sm

# Copy source code
COPY src/ src/

# Switch to non-root user
USER appuser

# Expose the application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()" || exit 1

# Default command: run the FastAPI app with uvicorn
CMD ["uvicorn", "pii_redactor.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
