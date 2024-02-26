from django.urls import path
from .views import AllQuestions, RandomQuestion, CourseQuestion, AllAnswers

urlpatterns = [
    path('course/<str:topic>/', CourseQuestion.as_view(), name='coursequestionapi'),
    path('random/<str:topic>/', RandomQuestion.as_view(), name='randomquestionapi'),
    path('allquestions/', AllQuestions.as_view(), name='allquestionsapi'),
    path('allanswers/', AllAnswers.as_view(), name='allanswersapi'),
    
]