# Use the official Python image as the base
FROM python:3.9

# Set the working directory inside the container
WORKDIR /app

# Copy the entire project into the container
COPY . .

# Install required Python packages directly
RUN pip install flask numpy pandas  # Add any other dependencies here

# Expose the application port (modify if needed)
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]
