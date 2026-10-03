# Trusted, already available Python/FastAPI base; build never installs packages.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
RUN mkdir -p /fixture && chown 10001:10001 /fixture
COPY --chown=10001:10001 app.py /fixture/app.py
ENV PYTHONPATH=/fixture PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /fixture
USER 10001:10001
ENTRYPOINT ["python"]
CMD ["-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "18081", "--no-access-log"]
