from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services.quiz_engine import generate_quiz
from django.conf import settings

class GenerateQuizView(APIView):
    """
    POST:
      body: {
        "context": "some text",
        "num_questions": 3,
        "quiz_type": "multiple-choice",
        "language": "English"   # optional, defaults to English if not provided
      }
    """
    def post(self, request):
        try:
            # No longer pulling openai_api_key from request
            context = request.data.get("context", "")
            num_questions = int(request.data.get("num_questions", 3))
            quiz_type = request.data.get("quiz_type", "multiple-choice")
            
            # NEW: Get language, default to "English"
            language = request.data.get("language", "English")

            # Use our own key from settings (or environment)
            openai_api_key = settings.OPENAI_API_KEY

            # Pass language to generate_quiz
            quiz_response = generate_quiz(openai_api_key, context, num_questions, quiz_type, language)
            return Response(quiz_response.dict(), status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



class ScoreQuizView(APIView):
    """
    POST:
      body: {
        "user_answers": [...],
        "correct_answers": [...]
      }
    """
    def post(self, request):
        try:
            user_answers = request.data.get("user_answers", [])
            correct_answers = request.data.get("correct_answers", [])
            
            if not user_answers:
                return Response(
                    status=status.HTTP_400_BAD_REQUEST
                )

            if len(user_answers) > len(correct_answers):
                return Response(
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Compare only the provided answers
            score = sum(1 for ua, ca in zip(user_answers, correct_answers) if ua == ca)
            return Response({"score": score, "total": len(correct_answers)}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

