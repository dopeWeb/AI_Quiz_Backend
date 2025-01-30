# quiz_app/urls.py
from django.urls import path
from .views import GenerateQuizView, ScoreQuizView

urlpatterns = [
    path('quiz', GenerateQuizView.as_view(), name='generate_quiz'),
    path('quiz/score', ScoreQuizView.as_view(), name='score_quiz'),
]
