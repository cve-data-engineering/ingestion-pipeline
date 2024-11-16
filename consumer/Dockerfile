# Use the official Python image as a base
FROM python:3.9-slim

WORKDIR /opt

COPY . /opt

RUN pip install -r /opt/consumer/requirements.txt

RUN pip install python-dotenv

# Run the main Python script
CMD ["python3", "consumer/main.py"]
