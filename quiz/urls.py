from django.urls import path
from .views import allquestions, QuestionSingleView

urlpatterns =[
    path('question/<int:pk>/', QuestionSingleView.as_view(), name='questionsingle'),
    path('', allquestions, name='allquestion'), 
]


