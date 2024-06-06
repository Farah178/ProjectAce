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

# Create necessary directories
RUN mkdir -p /eztime/django/site/static
RUN mkdir -p /eztime/django/site/static/frontend

# Create the media directories
RUN mkdir -p /eztime/django/site/media/file_attachment /eztime/django/site/media/leave_files /eztime/django/site/media/org_logo /eztime/django/site/media/pf_file_path /eztime/django/site/media/photo /eztime/django/site/media/user_profile_photo

# Copy the built front-end dist folder into the container
COPY dist /eztime/django/site/static/frontend

# Collect static files after copying the dist folder
RUN python manage.py collectstatic --noinput

# Copy Nginx configuration file
COPY nginx.conf /etc/nginx/sites-available/default

# Expose the port Gunicorn will run on
EXPOSE 8001

# Install Gunicorn
RUN pip install gunicorn

# Run database migrations and start the server
CMD service nginx start && \
    python manage.py makemigrations && \
    python manage.py migrate && \
    gunicorn --bind 0.0.0.0:8001 eztimeproject.wsgi:application
