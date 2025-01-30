# Use official Python image as base
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy requirements file to the working directory
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . .

# Expose the application port (modify if needed)
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]
