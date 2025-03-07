FROM python:3
ARG USER_ID=1000

USER 0
COPY sbomgrader /opt/sbomgrader/sbomgrader
COPY pdm.lock pyproject.toml README.md /opt/sbomgrader/
RUN python3 -m venv /opt/sbomgrader/.venv

RUN chown -R "${USER_ID}":0 /opt/sbomgrader
USER "${USER_ID}":0
ENV PATH=/opt/sbomgrader/.venv/bin:$PATH
ENV HOME=/opt/sbomgrader/
WORKDIR /opt/sbomgrader/
RUN pip install pdm
RUN pdm install
