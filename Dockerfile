# Minimal Python container image for the pr_cost_gate GitHub Action runner.
# Builds a lean image that installs only production dependencies.

FROM python:3.12-slim

# Metadata labels
LABEL org.opencontainers.image.title="pr_cost_gate"
LABEL org.opencontainers.image.description="Analyze PR diffs for AI review costs and security risks"
LABEL org.opencontainers.image.licenses="MIT"

# Prevent Python from writing .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create a non-root user for security
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Copy dependency specification first for layer caching
COPY pyproject.toml ./

# Install the package and its dependencies
# We copy the full source so that the package is importable
COPY pr_cost_gate/ ./pr_cost_gate/

RUN pip install --upgrade pip && \
    pip install \
        "PyGithub>=2.1.1" \
        "tiktoken>=0.6.0" \
        "PyYAML>=6.0.1" \
        "requests>=2.31.0" && \
    pip install --no-deps -e .

# Switch to non-root user
USER appuser

# The CLI entry point installed by pyproject.toml
ENTRYPOINT ["pr-cost-gate"]
