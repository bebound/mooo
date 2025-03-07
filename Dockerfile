FROM python:3.13-slim
RUN --mount=type=bind,source=.,target=/app,rw cd /app && pip install ./
RUN rm -rf /app
ENTRYPOINT ["mooo"]
CMD []
