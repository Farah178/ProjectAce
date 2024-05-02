FROM python:3

ENV PYTHONUNBUFFERED 1

WORKDIR /eztime/django

ADD . /eztime/django

COPY requirements.txt /eztime/django/requirements.txt

RUN pip install -r requirements.txt

COPY . /eztime/django

# Collect static files
RUN python manage.py collectstatic --noinput

# Install Nginx
RUN apt-get update && apt-get install -y nginx

# Copy Nginx configuration file
COPY nginx.conf /etc/nginx/sites-available/default

# Expose the port Gunicorn will run on
EXPOSE 8000

# Use Gunicorn to serve your application
CMD service nginx start && gunicorn --bind 0.0.0.0:8000 eztimeproject.wsgi:application

# CMD [ "python" , "manage.py", "makemigrations"]
# CMD [ "python" , "manage.py", "migrate"]


