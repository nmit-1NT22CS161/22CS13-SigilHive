FROM python:3.12-slim
 
WORKDIR /app
 
COPY sequential_attack_runner.py .
 
RUN pip install --no-cache-dir asyncssh langchain_google_genai langchain-core langgraph
 
CMD ["python", "sequential_attack_runner.py"]