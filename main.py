from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import List
from scipy.stats import zscore
from sklearn.neighbors import LocalOutlierFactor
import pandas as pd
import numpy as np


app = FastAPI()

# HTTP Basic authentication
security = HTTPBasic()

# Username and Password for basic authentication
USERNAME = 'NintexSari'
PASSWORD = 'NS2023'

# Model for the user
class User(BaseModel):
    name: str
    email: str
    password: str

# Model for the anomaly detection response
class AnomalyDetectionResponse(BaseModel):
    message: str
    anomalies_login: List[dict] 
    anomalies_password_change: List[dict]
    anomalies_failed_login: List[dict]
    # List[dict] - list containing dictionaries.

# List to store user data
users = []  # List of dictionaries - each dictionary represents a user with the attributes name, email, and password.
user_id_list = []  # List for users id

def get_user_by_id(user_id: int):
    for user in users:
        if user['id'] == user_id:
            return user
    return None

def generate_random_user_data_zscore():
    # Generate a random dataset for user behavior
    np.random.seed(10)  # for reproducibility
    user_data = pd.DataFrame({
        'user_id': np.repeat(np.arange(1, 101), 1),
        'login_frequency': np.random.normal(3, 2, 100),
        'password_change': np.random.normal(2,2, 100),
        'failed_login_attempts': np.random.normal(2,1, 100)
    })
    # np.arange(start, step), np.repeat(Input array, repeats)
    # np.random.normal(mean,std,size)
    # For each user I will check for anomalies in password change frequency, system login frequency, system login failure frequency.
    return user_data

def generate_random_user_data_LOF():
    
    np.random.seed(42)  # for reproducibility
    
    # Generate a random dataset for user behavior
    data_inliers = 0.3 * np.random.randn(90, 3) # 3 columns - each for a specific activity
    data_outliers = np.random.uniform(low=-4, high=4, size=(10, 3)) 
    # A 2D array representing 10 data points, each with 3 features, sampled uniformly from the specified range.
    data = np.concatenate((data_inliers + 2, data_outliers), axis=0)
    # data_inliers + 2 - This is done in order to shift the inliers away from the outliers.
    # Creates a clearer visual separation between the two classes in plots
    # Makes the task more challenging for anomaly detection. 

    user_data = pd.DataFrame({
        'user_id': np.arange(1, 101), #101-1=100=90+10
        'login_frequency': data[:, 0],
        'password_change': data[:, 1],
        'failed_login_attempts': data[:, 2]
    })
    # For each user I will check for anomalies in password change frequency, system login frequency, system login failure frequency.
    return user_data


# Function to check basic authentication
def check_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != USERNAME or credentials.password != PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials


# Endpoint for starting the program
@app.get("/", status_code=200) # 200 - Indicates that the request has succeeded.
def start_func():
    return {'message': 'Hello Nintex Team :)'}

# Endpoint to create a new user
@app.post("/users/", response_model=dict, status_code=201) 
# 201-Indicates that the request has succeeded and a new resource has been created as a result.
def create_user(user: User, credentials: HTTPBasicCredentials = Depends(check_basic_auth)):
# Receives a user parameter, which is an instance of the User Pydantic model.
# The function expects the request body to be a JSON object that can be validated against the User Pydantic model.
    new_user_id=len(user_id_list)+1 # Assign an id number for the new user   
    new_user = {'id': new_user_id, 'name': user.name, 'email': user.email, 'password': user.password} 
    # Assign user's details in new user dictionary
    users.append(new_user) # Appends the new_user dictionary to the users list
    user_id_list.append(new_user_id) # Add to users id list the new id
    return {'message': 'Successfully created user'}

# Endpoint to edit an existing user
@app.put("/users/{user_id}", response_model=dict, status_code=200) # 200 - Indicates that the request has succeeded.
def edit_user(user_id: int, updated_user: User, credentials: HTTPBasicCredentials = Depends(check_basic_auth)):   

    existing_user = get_user_by_id(user_id)
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found") # 404 - Not Found

    # Update user details
    existing_user['name'] = updated_user.name
    existing_user['email'] = updated_user.email
    existing_user['password'] = updated_user.password

    return {'message': "Successfully updated user", 'updated_user': updated_user}

# Endpoint to delete a user
@app.delete("/users/{user_id}", response_model=dict, status_code=200) # 200 - Indicates that the request has succeeded.
def delete_user(user_id: int, deleted_user: User, credentials: HTTPBasicCredentials = Depends(check_basic_auth)):   
    
    existing_user = get_user_by_id(user_id)
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    users.remove(existing_user)

    return {'message': "Successfully deleted user", 'deleted_user': existing_user}

# Endpoint to list all users
@app.get("/users/", response_model=List[User], status_code=200) # 200 - Indicates that the request has succeeded.
def list_users(credentials: HTTPBasicCredentials = Depends(check_basic_auth)):
    return users

# Endpoint for anomaly detection - Z- Score
@app.get("/anomaly-detection-zscore/", response_model=AnomalyDetectionResponse, status_code=200)
def anomaly_detection_zscore(credentials: HTTPBasicCredentials = Depends(check_basic_auth)):
    # Generate random user data for login frequencies, password change frequencies and failed login attempts
    user_data = generate_random_user_data_zscore()

    # Calculate z-scores for relevant user behavior
    user_data['zs_login_freq'] = zscore(user_data['login_frequency'])
    user_data['zs_password_change'] = zscore(user_data['password_change'])
    user_data['zs_failed_login'] = zscore(user_data['failed_login_attempts'])

    # Set a threshold for anomaly detection
    th_login = 2
    th_password_change = 2
    th_failed_login = 2

    # Identify anomalies based on z-scores
    anomal_login_freq = user_data[np.abs(user_data['zs_login_freq']) > th_login]
    anomal_password_change = user_data[np.abs(user_data['zs_password_change']) > th_password_change]
    anomal_failed_login = user_data[np.abs(user_data['zs_failed_login']) > th_failed_login]

    # Select specific data for the response (The details to be printed out)
    sel_data_login_freq = anomal_login_freq[['user_id', 'login_frequency', 'zs_login_freq']]
    sel_data_password_change = anomal_password_change[['user_id', 'password_change', 'zs_password_change']]
    sel_data_failed_login = anomal_failed_login[['user_id', 'failed_login_attempts', 'zs_failed_login']]

    # Convert selected data (DataFrames) to dictionaries
    data_login_freq = sel_data_login_freq.to_dict(orient='records')
    data_password_change = sel_data_password_change.to_dict(orient='records')
    data_failed_login = sel_data_failed_login.to_dict(orient='records')
    # ‘records’ : list like [{column -> value}, … , {column -> value}] (List[dict])
    
    return AnomalyDetectionResponse(
        message="Z- Score Anomaly detection completed",
        anomalies_login=data_login_freq,
        anomalies_password_change=data_password_change,
        anomalies_failed_login=data_failed_login
    )

"""
Anomaly Detection - Statistical Method - Z-score:

Z-scores are a way to compare results to a “normal” population.
z = (x – μ) / σ
Z-score is a statistical measurement that describes a value's relationship to the mean of a group of values. 
Z-score is measured in terms of standard deviations from the mean. 
If a Z-score is 0, it indicates that the data point's score is identical to the mean score. 
A Z-score of 1.0 would indicate a value that is one standard deviation from the mean. 
Z-scores may be positive or negative, with a positive value indicating the score is above the mean 
and a negative score indicating it is below the mean.
The Z-score is a measure that indicates how many standard deviations a data point is from the mean of a dataset.
A high Z-score (typically greater than a threshold, such as 2 or 3) indicates that the data point is far from the mean 
and can be considered an outlier. Similarly, a low Z-score (typically less than the negative threshold) suggests that 
the data point is significantly below the mean, also indicating an anomaly.
"""

#Bonus Challenge

#Endpoint for anomaly detection - Local Outlier Factor (LOF)
@app.get("/anomaly-detection-lof/", response_model=AnomalyDetectionResponse, status_code=200)
def anomaly_detection_LOF(credentials: HTTPBasicCredentials = Depends(check_basic_auth)):
    # Generate random user data for login frequencies, password change frequencies and failed login attempts
    user_data = generate_random_user_data_LOF()

    # Fit the Local Outlier Factor model
    clf = LocalOutlierFactor(n_neighbors=20, contamination=0.1)
    # Number of neighbors to consider -20 - default value.
    # Contamination set to 0.1 (proportion of outliers) - The LOF algorithm is configured to consider 
    # approximately 10% of the data points as outliers when fitting the model: Calac: 10/100=0.1
    # sklearn.neighbors.LocalOutlierFactor: Contamination should be in the range (0, 0.5].

    # Calculate LOF for relevant user behavior
    user_data['LOF_login_freq'] = clf.fit_predict(user_data['login_frequency'].values.reshape(-1, 1))
    user_data['LOF_password_change'] = clf.fit_predict(user_data['password_change'].values.reshape(-1, 1))
    user_data['LOF_failed_login'] = clf.fit_predict(user_data['failed_login_attempts'].values.reshape(-1, 1))
    # fit_predict(X[, y]) - Fit the model to the training set X and return the labels.
    # Label is 1 for an inlier and -1 for an outlier according to the LOF score and the contamination parameter.
    # .values.reshape(-1, 1) - pandas dataframe is 1D array and fit_predict input needs to be a 2D array. 

    # Identify anomalies based on LOF calc
    anomal_login_freq = user_data[user_data['LOF_login_freq']==-1]
    anomal_password_change = user_data[user_data['LOF_password_change']==-1]
    anomal_failed_login = user_data[user_data['LOF_failed_login']==-1]

    # Select specific data for the response (The details to be printed out)
    sel_data_login_freq = anomal_login_freq[['user_id', 'login_frequency', 'LOF_login_freq']]
    sel_data_password_change = anomal_password_change[['user_id', 'password_change', 'LOF_password_change']]
    sel_data_failed_login = anomal_failed_login[['user_id', 'failed_login_attempts', 'LOF_failed_login']]

    # Convert selected data to dictionaries
    data_login_freq = sel_data_login_freq.to_dict(orient='records')
    data_password_change = sel_data_password_change.to_dict(orient='records')
    data_failed_login = sel_data_failed_login.to_dict(orient='records')
    # ‘records’ : list like [{column -> value}, … , {column -> value}] (List[dict])
    
    return AnomalyDetectionResponse(
        message="LOF Anomaly detection completed",
        anomalies_login=data_login_freq,
        anomalies_password_change=data_password_change,
        anomalies_failed_login=data_failed_login
    )

"""
The Local Outlier Factor (LOF) algorithm is an unsupervised anomaly detection method which computes 
the local density deviation of a given data point with respect to its neighbors. 
It considers as outliers the samples that have a substantially lower density than their neighbors.
"""