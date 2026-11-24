FROM python:3.12-slim
WORKDIR /app
COPY cthunt ./cthunt
VOLUME /data
ENTRYPOINT ["python", "-m", "cthunt", "--db", "/data/cthunt.db"]
CMD ["run", "--follow"]
