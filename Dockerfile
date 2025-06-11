
# Use a lightweight Python image as the base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Ensure static assets are accessible
RUN mkdir -p /app/static && chmod 755 /app/static

# Create a non-root user for security
RUN useradd -ms /bin/bash appuser

# Set up permissions for sensitive directories and files
# Secure directory for encryption keys
RUN mkdir -p /home/appuser/.keys && chmod 700 /home/appuser/.keys
RUN chown -R appuser:appuser /home/appuser/.keys

# Secure directory for database storage
RUN mkdir -p /home/appuser/data && chmod 700 /home/appuser/data
RUN chown -R appuser:appuser /home/appuser/data

# If a database file is needed, create it with appropriate permissions
RUN touch /home/appuser/data/secure_data.db && chmod 600 /home/appuser/data/secure_data.db
RUN chown appuser:appuser /home/appuser/data/secure_data.db

# Set correct permissions for the /app directory
RUN chmod -R 755 /app && chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Expose the port that waitress will listen on
EXPOSE 3000

# Start the Flask application using waitress
CMD ["waitress-serve", "--host=0.0.0.0", "--port=3000", "--threads=4", "main:app"]
