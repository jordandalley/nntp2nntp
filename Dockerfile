# Use a lightweight Python image as the base
FROM python:slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for pyOpenSSL
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev

# Copy the application files into the container
COPY build/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY build/nntp2nntp.py .
COPY build/nntppost.py .

# Define the entrypoint

CMD ["python", "nntp2nntp.py"]
