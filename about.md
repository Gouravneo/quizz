# Django Quiz Api
## Project Description

This is a django quiz app with a web based API that allows users to take quizzes and view their results. This project was built using django rest framework with JWT authentication. The API has several endpoints which allows users to create quizzes, take quizzes, view their results and view questions by category. The API provides a secure and scalable platform for hosting quizzes online. It is designed to be flexible, easy to use and integrate with other systems. Overall, this django quiz app REST API is a reliable and efficient solution for hosting quizzes online. It provides a seamless user experience and is suitable for both small and large scale applications.


## Installation
To install the Django Quiz API follow these steps;
1. Set up locally: **cd desktop/documents**
2. Clone the repository: **git clone https://github.com/MajorTomidev/QUIZ_API.git**
3. Create a virtual environment and activate it: **python -m venv env or virtualenv env** and **source env/bin/activate**
4. Install the dependencies: **pip install -r requirements.txt**
5. Run the migrations: **python manage.py migrate**
6. Start the server: **python manage.py runserver**

## Technologies Used 
- Django
- Django Restframework
- JWT Authentication
- Pillow
- Github

## API EndPoints
- **GET /api/allquestions/ :** Get a list of all Questions
- **GET /api/allanswers/ :** Get a list of all Answers
- **GET /api/course/str:topic/ :** Get Questions on a particular course
- **GET /api/random/str:topic/ :** Get Random Questions on a particular course


## JWT API EndPoints
- **GET /api/schema/ :** View Documentation
- **GET /api/schema/redoc/ :** To download your Schema.yml
- **GET /api/schema/swagger-ui/ :** View the Swagger UI of documentation
- **POST /api/token/ :** Create a token using a pair of user credentials
- **POST /api/token/refresh/ :** Generate a new token based on the same user credentials

## Users Endpoints
- **GET /users/create/ :** To create a new user
- **GET&PUT /users/updateretrieve/ :** To view and update a user instance 
