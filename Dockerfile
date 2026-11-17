# The Privacy proxy as an image (#3). Built from the repo only: the deny-list, the
# keys file and the spend database are mounted at run time (docker-compose.example.yml)
# and never copied in -- .dockerignore lets through only the files below.
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
# /app in both stages: a venv hard-codes the path it was made at.
# Dependencies first, so a code change doesn't reinstall them.
COPY pyproject.toml uv.lock README.md providers.yaml ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
# Non-editable: the wheel carries providers.yaml (pyproject's force-include).
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
# A fixed uid and gid, so the host can grant group 10001 the 0640 files under
# /etc/privacy-proxy (README, "Running it as a service"). Without --gid the group
# gets the next free system gid (999), and the proxy can't read its deny-list.
RUN groupadd --system --gid 10001 privacyproxy \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin privacyproxy \
 && mkdir -p /var/lib/privacy-proxy && chown privacyproxy /var/lib/privacy-proxy
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    SPEND_DB_PATH=/var/lib/privacy-proxy/spend.db
USER privacyproxy
EXPOSE 8787
# 0.0.0.0 is the container's own network only: publish the port on a loopback, or
# behind a proxy you trust (docker-compose.example.yml binds 127.0.0.1).
ENTRYPOINT ["privacy-proxy", "--host", "0.0.0.0", "--port", "8787"]
