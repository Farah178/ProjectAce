# Use an official Python runtime as the base image
FROM python:3

# Set environment variables
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /eztime/django

# Install ODBC driver dependencies
RUN apt-get update && apt-get install -y \
    unixodbc \
    unixodbc-dev \
    odbcinst \
    build-essential \
    libssl-dev \
    libffi-dev \
    curl \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# Install Microsoft ODBC Driver for SQL Server
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && curl https://packages.microsoft.com/config/debian/10/prod.list > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y msodbcsql17

# Install pyodbc
RUN pip install pyodbc

# Copy the current directory contents into the container at /eztime/django
ADD . /eztime/django

# Install any needed packages specified in requirements.txt
COPY requirements.txt /eztime/django/requirements.txt
RUN pip3 install -r requirements.txt

# Collect static files
RUN python manage.py collectstatic --noinput

# Copy Nginx configuration file
COPY nginx.conf /etc/nginx/sites-available/default

# Expose the port Gunicorn will run on
EXPOSE 8000

# Install Gunicorn
RUN pip3 install gunicorn

# Use Gunicorn to serve your application
CMD service nginx start && gunicorn --bind 0.0.0.0:8000 eztimeproject.wsgi:application
