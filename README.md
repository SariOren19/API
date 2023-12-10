# **API service for managing users and anomaly detection algorithms to identify unusual user activities**

## **Overview**

Python-based API service for managing users within a system, with an added focus on anomaly detection to identify unusual user activities. 

It includes:
- User Management:
  - Endpoint to add a new user.
  - Endpoint to modify details of an existing user.
  - Endpoint to remove a user.
  - Endpoint to return a list of all users with their details.
- Anomaly Detection algorithms that flags unusual activities based on user behavior:
  - Statistical method: z-score
  - Machine learning method: Local Outlier Factor - LOF.
- Basic authentication to secure the API endpoints, including the anomaly detection feature. 


## **Setup**

### **Prerequisites**

Make sure you have the following installed:

- Docker: Installation Guide
- Python 3.8 or higher

### **Installation**
- Clone the repository:
  - git clone <repository_url>
  cd NintexAPI
- Build the Docker image:
  - docker build -t nintexapi .

### **Running the Service**

- Start the Docker Container
- Run the Docker container, exposing port 4000 on your local machine:
  - docker run -p 4000:80 nintexapi
- The service will be accessible at http://localhost:4000.
- Access the API Documentation
  Visit http://localhost:4000/docs for the interactive API documentation, where you can explore and test the available endpoints.

## **Authentication**
- The service uses HTTP Basic Authentication. Use the following credentials:
  - Username: NintexSari
  - Password: NS2023
## **User Management**

### **Create a New User**
- To create a new user, use the following endpoint:
  - POST /users/
- Provide user details in the request body:
  - {"name":"string","email":"string","password":"string"}

### **Edit an Existing User**
- To edit an existing user, use the following endpoint:
  - PUT /users/{user_id}
- Provide the user ID and updated user details in the request body.

### **Delete a User**
- To delete a user, use the following endpoint:
  - DELETE /users/{user_id}
- Provide the user ID in the request.

### **List All Users**
- To list all users, use the following endpoint:
  - GET /users/

## **Anomaly Detection**

### **Z-Score Anomaly Detection**

- To perform Z-Score anomaly detection, use the following endpoint:
  - GET /anomaly-detection-zscore/
- This will return anomalies in login frequency, password change frequency, and failed login attempts based on Z-Score calculations.

### **LOF Anomaly Detection**

- To perform LOF anomaly detection, use the following endpoint:
  - GET /anomaly-detection-lof/
- This will return anomalies in login frequency, password change frequency, and failed login attempts based on the Local Outlier Factor algorithm.

## **Additional Information**

- The service uses FastAPI, a modern, fast web framework for building APIs with Python 3.7+.
- Anomaly detection is based on statistical methods (Z-Score) and machine learning (LOF).

## **Feedback and Support**
For feedback or support, contact [sari.oren193@gmail.com].
