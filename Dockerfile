# Use an official Python runtime as the base image
FROM python:3

# Set environment variables
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /eztime/django

# Copy the current directory contents into the container at /eztime/django
ADD . /eztime/django

# Install any needed packages specified in requirements.txt
COPY requirements.txt /eztime/django/requirements.txt
RUN pip3 install -r requirements.txt

# Collect static files
# RUN python manage.py collectstatic --noinput

# Install Nginx
RUN apt-get update && apt-get install -y nginx

# Copy Nginx configuration file
COPY nginx.conf /etc/nginx/sites-available/default

# Expose the port Gunicorn will run on
EXPOSE 8000

# Install Gunicorn
RUN pip3 install gunicorn

# Use Gunicorn to serve your application
CMD service nginx start && gunicorn --bind 0.0.0.0:8000 eztimeproject.wsgi:application

