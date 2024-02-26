from django.shortcuts import render
from .models import Question, Answer
from django.views.generic import DetailView


def allquestions(request):
    question = Question.objects.all()
    answer = Answer.objects.all()
   
    return render(request,  {"question": question, 'answer': answer})


class QuestionSingleView(DetailView):
    model = Question
    context_object_name = 'questionsingle'
