# Use an official Python runtime as the base image
FROM python:3

# Set environment variables
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /eztime/django

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    curl \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /eztime/django
ADD . /eztime/django

# Copy the SSL certificate into the container
COPY DigiCertGlobalRootCA.crt.pem /eztime/django/ssl/DigiCertGlobalRootCA.crt.pem

# Install any needed packages specified in requirements.txt
COPY requirements.txt /eztime/django/requirements.txt
RUN pip install -r requirements.txt

# Collect static files
RUN python manage.py collectstatic --noinput

# Copy Nginx configuration file
COPY nginx.conf /etc/nginx/sites-available/default

# Expose the port Gunicorn will run on
EXPOSE 8000

# Install Gunicorn
RUN pip install gunicorn

# Run database migrations and start the server
CMD service nginx start && \
    python manage.py makemigrations && \
    python manage.py migrate && \
    gunicorn --bind 0.0.0.0:8000 eztimeproject.wsgi:application
