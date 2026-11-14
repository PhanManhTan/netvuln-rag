FROM netvuln-build:ubuntu22
RUN python3 -m pip install --no-cache-dir 'cfn-lint>=1.41,<2' 'pytest>=8,<9' \
    'fastapi>=0.115,<1' 'uvicorn>=0.34,<1' 'pydantic>=2.10,<3' 'httpx>=0.27,<1' 'boto3>=1.40,<2'
