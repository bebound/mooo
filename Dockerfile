FROM python:3.12-slim
RUN --mount=type=bind,source=.,target=/app,rw cd /app && pip install ./
RUN rm -rf /app
ENTRYPOINT ["mooo"]
CMD []
