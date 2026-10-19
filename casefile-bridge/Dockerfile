# The bridge core runs on the Python standard library; the research tools it
# drives are installed separately (or mounted) by the operator. The optional
# geo extras improve phone and IP precision.
FROM python:3.12-slim

WORKDIR /srv/casefile-bridge
COPY pyproject.toml README.md requirements.txt ./
COPY casefile ./casefile

RUN pip install --no-cache-dir '.[geo]'

# Cases live under the bind-mounted app cache, not the image.
ENV CASEFILE_STORE=/app/.gev-cache/casefile
ENTRYPOINT ["python", "-m", "casefile"]
CMD ["serve", "--host", "0.0.0.0", "--port", "7733"]
