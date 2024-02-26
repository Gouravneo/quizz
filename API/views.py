from rest_framework import generics
from rest_framework.response import Response
from quiz.models import Question, Answer
from .serializers import QuestionSerializer, RandomQuestionSerializer, CourseSerializer, AnswerSerializer
from rest_framework.views import APIView

# Create your views here.

class AllQuestions(generics.ListAPIView):

    serializer_class = QuestionSerializer
    queryset = Question.objects.all()

class AllAnswers(generics.ListAPIView):

    serializer_class = AnswerSerializer
    queryset = Answer.objects.all()

class RandomQuestion(APIView):

    def get(self, request, format=None, **kwargs):
        question = Question.objects.filter(course=kwargs['topic']).order_by('?')[:1]
        serializer = RandomQuestionSerializer(question, many=True)
        return Response(serializer.data)
    
class CourseQuestion(APIView):

    def get(self, request, format=None, **kwargs):
        quiz = Question.objects.filter(course=kwargs['topic'])
        serializer = CourseSerializer(quiz, many=True)
        return Response (serializer.data)
    

