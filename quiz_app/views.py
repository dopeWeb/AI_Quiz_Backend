from datetime import date
from django.utils import timezone
from typing import List, Dict, Any
from django.shortcuts import get_object_or_404
from django.views import View
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services.quiz_engine import generate_quiz
from django.conf import settings
from rapidfuzz import fuzz
import unicodedata
import re
from nltk.stem import SnowballStemmer
import pymorphy2  
from sentence_transformers import SentenceTransformer, util
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .models import Quiz, Question
from rest_framework.permissions import IsAuthenticated
import json
from django.http import Http404, HttpRequest, HttpResponseBadRequest, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests 
import requests  
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_str
import logging
from django.utils.encoding import force_bytes
from .auth_utils import format_duration, get_lockout_info, update_lockout_info, FAILURE_LIMIT, LOCK_TIME_LEVELS

# this module’s own logger → goes to myapp.log
logger = logging.getLogger("myapp")
frontend_logger = logging.getLogger("frontend")
uidb64 = urlsafe_base64_encode(force_bytes(User.pk))


class GenerateQuizView(APIView):
    def post(self, request):
        # Only enforce generation limit for non-superusers.
        if not request.user.is_superuser:
            # Use today's date as a string.
            today_str = date.today().isoformat()
            # Retrieve the generation count and generation date from the session.
            generation_count = request.session.get("quiz_generation_count", 0)
            generation_date = request.session.get("quiz_generation_date", today_str)

            # 🔍 Debug logging
            logger.debug("Today: %s", today_str)
            logger.debug("Stored generation_date: %s, generation_count: %s", generation_date, generation_count)

            # If the stored generation_date is not today, reset the counter.
            if generation_date != today_str:
                generation_count = 0
                generation_date = today_str
                request.session["quiz_generation_count"] = 0
                request.session["quiz_generation_date"] = today_str
                logger.debug("Reset generation counter for new day. New generation_date: %s", generation_date)

            # Get the number of questions requested.
            num_questions = int(request.data.get("num_questions", 3))
            logger.debug("Requested num_questions: %s", num_questions)

            # Check if adding these questions would exceed today's limit.
            if generation_count + num_questions > 30:
                logger.debug("Limit exceeded: %s + %s > 30", generation_count, num_questions)
                return Response(
                    {"error": "Daily generation limit reached (30 questions per day)."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        try:
            # Retrieve parameters.
            context = request.data.get("context", "")
            num_questions = int(request.data.get("num_questions", 3))
            quiz_type = request.data.get("quiz_type", "multiple-choice")
            language = request.data.get("language", "English")

            # 🔍 Debug logging
            logger.debug(
                "Generating quiz with context=%r, num_questions=%s, quiz_type=%s, language=%s",
                context, num_questions, quiz_type, language
            )

            openai_api_key = settings.OPENAI_API_KEY
            quiz_response = generate_quiz(openai_api_key, context, num_questions, quiz_type, language)
            quiz_data = quiz_response.dict()  # Convert structured output to dict


            # Transform for multiple-choice: fill each question with option fields.
            if quiz_type == "multiple-choice" and "display" in quiz_data:
                questions = quiz_data.get("questions", [])
                display_alternatives = quiz_data["display"].get("alternatives", [])
                display_answers = quiz_data["display"].get("answers", [])
                transformed_questions = []
                for i, q in enumerate(questions):
                    q_text = q if isinstance(q, str) else q.get("text", "")
                    alts = display_alternatives[i] if i < len(display_alternatives) else []
                    correct = display_answers[i] if i < len(display_answers) else ""
                    transformed_question = {
                        "question_id": i,
                        "question_type": "MC",
                        "text": q_text,
                        "option_a": alts[0] if len(alts) > 0 else "",
                        "option_b": alts[1] if len(alts) > 1 else "",
                        "option_c": alts[2] if len(alts) > 2 else "",
                        "option_d": alts[3] if len(alts) > 3 else "",
                        "correct_answer": correct,
                    }
                    transformed_questions.append(transformed_question)
                quiz_data["questions"] = transformed_questions
                quiz_data["display"]["questions"] = [q["text"] for q in transformed_questions]
                logger.debug("Transformed multiple-choice questions")

            # Update generation counter for non-superusers.
            if not request.user.is_superuser:
                generation_count = request.session.get("quiz_generation_count", 0)
                new_count = generation_count + num_questions
                request.session["quiz_generation_count"] = new_count
                request.session["quiz_generation_date"] = date.today().isoformat()
                logger.debug("Updated session generation_count: %s → %s", generation_count, new_count)

            return Response(quiz_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.debug("Exception in GenerateQuizView: %s", e)
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



class SaveQuizView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            dashboard = request.data.get('dashboard')
            quiz_data = request.data.get('quiz_data')
            logger.debug("Received SaveQuizView POST: dashboard=%r, quiz_data=%s", dashboard, 
                         type(quiz_data).__name__)

            if not dashboard:
                logger.debug("Validation error: missing dashboard")
                return Response({"error": "Dashboard name is required."},
                                status=status.HTTP_400_BAD_REQUEST)
            if not quiz_data:
                logger.debug("Validation error: missing quiz_data")
                return Response({"error": "Quiz data is required."},
                                status=status.HTTP_400_BAD_REQUEST)

            # If quiz_data comes in as a string, try to parse it
            if isinstance(quiz_data, str):
                try:
                    quiz_data = json.loads(quiz_data)
                    logger.debug("Parsed quiz_data JSON string")
                except Exception as e:
                    logger.debug("Failed to parse quiz_data string: %s", e)
                    return Response({"error": "Invalid quiz data format."},
                                    status=status.HTTP_400_BAD_REQUEST)

            questions = quiz_data.get('questions')
            if not questions or not isinstance(questions, list) or len(questions) == 0:
                logger.debug("Validation error: no questions list")
                return Response({"error": "No questions found for this quiz."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Determine language
            allowed_languages = ["English", "Spanish", "Russian", "German", "French", "Chinese"]
            language = quiz_data.get('language')
            if language not in allowed_languages:
                logger.debug("Language %r not allowed, defaulting to English", language)
                language = "English"
            else:
                logger.debug("Using language: %s", language)

            # Existing vs new quiz
            existing_quiz = Quiz.objects.filter(
                title__iexact=dashboard,
                created_by=request.user,
                is_deleted=False
            ).first()
            if existing_quiz:
                quiz = existing_quiz
                logger.debug("Updating existing quiz (id=%s) for user %s", quiz.pk, request.user)
            else:
                quiz = Quiz.objects.create(
                    title=dashboard,
                    language=language,
                    created_by=request.user
                )
                logger.debug("Created new quiz (id=%s) for user %s", quiz.pk, request.user)

            # Loop & create questions
            for idx, q in enumerate(questions):
                logger.debug("Processing question %d: %r", idx, q)
                if not isinstance(q, dict):
                    # convert shorthand
                    question_dict = {"text": q}
                    if "alternatives" in quiz_data and len(quiz_data["alternatives"]) > idx:
                        question_dict["question_type"] = "MC"
                        alts = quiz_data["alternatives"][idx]
                        question_dict.update({
                            "option_a": alts[0] if len(alts) > 0 else "",
                            "option_b": alts[1] if len(alts) > 1 else "",
                            "option_c": alts[2] if len(alts) > 2 else "",
                            "option_d": alts[3] if len(alts) > 3 else "",
                        })
                    else:
                        ans = quiz_data.get("answers", [])[idx] if len(quiz_data.get("answers", [])) > idx else ""
                        if ans.lower() in ["true", "false"]:
                            question_dict["question_type"] = "TF"
                            question_dict["tf_option_true"] = "True"
                            question_dict["tf_option_false"] = "False"
                        else:
                            question_dict["question_type"] = "OE"
                    question_dict["correct_answer"] = quiz_data.get("answers", [])[idx] or ""
                    q = question_dict
                    logger.debug("Converted to dict: %r", q)

                q_type = q.get('question_type', 'OE')
                if q_type == 'MC':
                    question = Question.objects.create(
                        quiz=quiz,
                        text=q.get('text', ''),
                        question_type='MC',
                        option_a=q.get('option_a', ''),
                        option_b=q.get('option_b', ''),
                        option_c=q.get('option_c', ''),
                        option_d=q.get('option_d', ''),
                        correct_answer=q.get('correct_answer', '')
                    )
                    logger.debug("Created MC question id=%s", question.pk)

                elif q_type == 'TF':
                    question = Question.objects.create(
                        quiz=quiz,
                        text=q.get('text', ''),
                        question_type='TF',
                        tf_option_true=q.get('tf_option_true', 'True'),
                        tf_option_false=q.get('tf_option_false', 'False'),
                        correct_answer=q.get('correct_answer', '')
                    )
                    logger.debug("Created TF question id=%s", question.pk)

                else:
                    question = Question.objects.create(
                        quiz=quiz,
                        text=q.get('text', ''),
                        question_type='OE',
                        correct_answer=q.get('correct_answer', '')
                    )
                    logger.debug("Created OE question id=%s", question.pk)

            logger.debug("Finished saving quiz (id=%s) with %d questions", quiz.pk, len(questions))
            return Response({"message": "Quiz saved successfully."}, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.debug("Exception in SaveQuizView: %s", e)
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)




# Configure language support
DEFAULT_LANGUAGE = "english"
SUPPORTED_LANGUAGES = ["english", "spanish", "russian", "german", "french", "chinese"]

# Create a dictionary of stemmers for supported languages (except Chinese).
STEMMER_DICT = {lang: SnowballStemmer(lang) for lang in SUPPORTED_LANGUAGES if lang != "chinese"}

# Initialize Russian morphological analyzer
morph_analyzer = pymorphy2.MorphAnalyzer()

# Initialize the semantic similarity model (multilingual) with a stronger model.
semantic_model = SentenceTransformer('paraphrase-xlm-r-multilingual-v1')
   

def normalize_text(text: str, language: str = DEFAULT_LANGUAGE) -> str:

    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.lower().strip()
    # Auto-detect Chinese by checking for any character in the common Chinese range.
    if language.lower() == "chinese" or re.search(r'[\u4e00-\u9fff]', normalized):
        import jieba
        tokens = list(jieba.cut(normalized, cut_all=False))
        normalized = " ".join(tokens)
    else:
        # Allow letters, digits, whitespace, hyphens, apostrophes, and "=".
        normalized = re.sub(r"[^\w\s\-'=]", "", normalized, flags=re.UNICODE)
    return normalized


def stem_word_multi(word: str, language: str = DEFAULT_LANGUAGE) -> str:
 
    lang = language.lower()
    if lang == "russian":
        lemma = morph_analyzer.parse(word)[0].normal_form
        return lemma
    elif lang in STEMMER_DICT:
        stemmed = STEMMER_DICT[lang].stem(word)
        return stemmed
    return word


def tokenize_text(text: str, language: str) -> List[str]:

    # If text contains Chinese, use jieba regardless of language parameter.
    if language.lower() == "chinese" or re.search(r'[\u4e00-\u9fff]', text):
        import jieba
        tokens = list(jieba.cut(text, cut_all=False))
        return tokens
    tokens = text.split()
    return tokens


def token_match_ratio(concept_tokens: List[str], answer_tokens: List[str], token_threshold: int = 90) -> float:

    if not concept_tokens:
        return 0.0
    matched_count = 0
    for token in concept_tokens:
        for a_token in answer_tokens:
            ratio = fuzz.ratio(token, a_token)
            if ratio >= token_threshold:
                matched_count += 1
                break
    ratio_final = matched_count / len(concept_tokens)
    return ratio_final


def check_relevance(student_answer: str, correct_answer: str, language: str = DEFAULT_LANGUAGE) -> bool:
 
    student_norm = normalize_text(student_answer, language)
    correct_norm = normalize_text(correct_answer, language)
    relevance_score = fuzz.token_set_ratio(student_norm, correct_norm)
    return relevance_score >= 50


def semantic_similarity(text1: str, text2: str) -> float:
 
    embedding1 = semantic_model.encode(text1, convert_to_tensor=True)
    embedding2 = semantic_model.encode(text2, convert_to_tensor=True)
    cosine_sim = util.cos_sim(embedding1, embedding2).item()  # value between 0 and 1
    return cosine_sim * 100


def check_semantic_similarity_percentage(
    student_answer: str,
    correct_answer: str,
    language: str = DEFAULT_LANGUAGE,
    question_text: str = ""
) -> Dict[str, Any]:
    # Normalize texts using language-specific processing.
    student_norm = normalize_text(student_answer, language)
    correct_norm = normalize_text(correct_answer, language)
    
    # Check if student just copied the question.
    if question_text:
        question_norm = normalize_text(question_text, language)
        if student_norm == question_norm:
            return {
                "text_similarity_percentage": 0.0,
                "semantic_similarity_percentage": 0.0,
                "overall_score": 0.0,
                "result": "incorrect",
            }
    
    # Exact match check.
    if student_norm == correct_norm:
        return {
            "text_similarity_percentage": 100.0,
            "semantic_similarity_percentage": 100.0,
            "overall_score": 100.0,
            "result": "correct",
        }
    
    # Use tokenize_text to get tokens.
    tokens = tokenize_text(student_norm, language)
    # For Chinese, require at least 5 tokens; for others, at least 3 tokens.
    if (language.lower() == "chinese" or re.search(r'[\u4e00-\u9fff]', student_norm)) and len(tokens) < 5:
        return {
            "text_similarity_percentage": 0.0,
            "semantic_similarity_percentage": 0.0,
            "overall_score": 0.0,
            "result": "incorrect",
        }
    elif not (language.lower() == "chinese" or re.search(r'[\u4e00-\u9fff]', student_norm)) and len(tokens) < 3:
        return {
            "text_similarity_percentage": 0.0,
            "semantic_similarity_percentage": 0.0,
            "overall_score": 0.0,
            "result": "incorrect",
        }
    
    if not check_relevance(student_answer, correct_answer, language):
        logger.debug("DEBUG: Warning: Student answer is not very relevant to the correct answer.")
    
    # Compute fuzzy match score using token_set_ratio for better tolerance of extra content.
    global_fuzzy = fuzz.token_set_ratio(student_norm, correct_norm)
    global_fuzzy = min(global_fuzzy, 100)  # Cap at 100
    
    # Compute global semantic similarity.
    global_semantic = semantic_similarity(student_norm, correct_norm)
    global_semantic = min(global_semantic, 100)  # Cap at 100
    
    # Combine the fuzzy and semantic scores using a weighted average (30% fuzzy, 70% semantic).
    combined_score = (0.3 * global_fuzzy) + (0.7 * global_semantic)
    combined_score = min(combined_score, 100)  # Cap at 100
    
    # Adjust thresholds for determining the result.
    if combined_score >= 40:
        result = "correct"
    elif combined_score >= 20:
        result = "partially correct"
    else:
        result = "incorrect"
    
    
    return {
        "text_similarity_percentage": round(global_fuzzy, 2),
        "semantic_similarity_percentage": round(global_semantic, 2),
        "overall_score": round(combined_score, 2),
        "result": result,
    }



class ScoreQuizView(APIView):
    def post(self, request):
        try:
            user_answers = request.data.get("user_answers", [])
            correct_answers = request.data.get("correct_answers", [])
            quiz_type = request.data.get("quiz_type", "")
            questions = request.data.get("questions", [])
            language = request.data.get("language", DEFAULT_LANGUAGE)

            logger.debug("ScoreQuizView POST start")
            logger.debug("  user_answers=%r", user_answers)
            logger.debug("  correct_answers=%r", correct_answers)
            logger.debug("  quiz_type=%r, language=%r", quiz_type, language)
            logger.debug("  questions=%r", questions)

            if not user_answers:
                logger.debug("  No user answers provided, returning 400")
                return Response({"error": "No user answers provided."},
                                status=status.HTTP_400_BAD_REQUEST)

            if len(user_answers) != len(correct_answers):
                logger.debug("  Mismatch lengths: %d vs %d", len(user_answers), len(correct_answers))
                return Response(
                    {"error": "Number of user answers does not match number of correct answers."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            total_score = 0
            score_details = []

            for i, user_answer in enumerate(user_answers):
                correct_answer = correct_answers[i]
                question_text = questions[i] if i < len(questions) else ""

                logger.debug("Processing question %d", i)
                logger.debug("  user_answer=%r", user_answer)
                logger.debug("  correct_answer=%r", correct_answer)
                logger.debug("  question_text=%r", question_text)

                concept_check = check_semantic_similarity_percentage(
                    user_answer,
                    correct_answer,
                    language,
                    question_text
                )

                logger.debug(
                    "  similarity check -> text:%s semantic:%s overall:%s",
                    concept_check["text_similarity_percentage"],
                    concept_check["semantic_similarity_percentage"],
                    concept_check["overall_score"]
                )

                if concept_check["overall_score"] >= 50:
                    result = "correct"
                    total_score += 1
                elif concept_check["overall_score"] >= 25 or concept_check["text_similarity_percentage"] >= 80:
                    result = "partially correct"
                else:
                    result = "incorrect"

                logger.debug("  result for question %d: %s", i, result)

                detail = {
                    "question_index": i,
                    "type": quiz_type,
                    "user_answer": user_answer,
                    "correct_answer": correct_answer,
                    "result": result
                }

                if quiz_type not in ["multiple-choice", "true-false"]:
                    detail.update({
                        "text_similarity_percentage": concept_check["text_similarity_percentage"],
                        "semantic_similarity_percentage": concept_check["semantic_similarity_percentage"],
                        "overall_score": concept_check["overall_score"]
                    })

                score_details.append(detail)

            logger.debug(
                "ScoreQuizView complete -> total_score=%d out_of=%d details=%r",
                total_score,
                len(correct_answers),
                score_details
            )

            return Response(
                {"score": total_score, "total": len(correct_answers), "details": score_details},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.debug("ScoreQuizView exception: %s", str(e), exc_info=True)
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


# Custom registration view as an API endpoint
class RegisterView(APIView): 
    def post(self, request):
        # Retrieve fields from the request data.
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        
        # Validate that username, email, and password are provided.
        if not username or not email or not password:
            return Response(
                {"error": "Username, email, and password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check for an existing user with the same username.
        if User.objects.filter(username=username).exists():
            return Response(
                {"error": "Username already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check for an existing user with the same email.
        if User.objects.filter(email=email).exists():
            return Response(
                {"error": "Email already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create the new user and mark the account as inactive until email confirmation.
        user = User.objects.create_user(username=username, email=email, password=password)
        user.is_active = False
        user.save()
        
        # Generate an email confirmation token.
        token = default_token_generator.make_token(user)
        
        # Construct the confirmation URL.
        confirmation_url = f"{request.scheme}://{request.get_host()}/api/confirm-email/{user.pk}/{token}/"
        
        # Compose both the plain-text and HTML email messages.
        subject = "Confirm Your Email"
        plain_message = (
            f"Hi {username},\n\n"
            "Thank you for registering. Please use the link below to verify your email address and complete your registration:\n\n"
            f"{confirmation_url}\n\n"
            "If you did not register for this account, please ignore this email."
        )
        html_message = f"""
        <html>
          <body>
            <p>Hi {username},</p>
            <p>Thank you for registering. Please click the link below to verify your email address and complete your registration:</p>
            <p><a href="{confirmation_url}">Verify Your Email Address</a></p>
            <p>If you did not register for this account, please ignore this email.</p>
          </body>
        </html>
        """
        
        from_email = settings.DEFAULT_FROM_EMAIL  # Ensure DEFAULT_FROM_EMAIL is set in settings.py.
        recipient_list = [email]
        
        # Send the confirmation email with an HTML message.
        send_mail(subject, plain_message, from_email, recipient_list,
                  fail_silently=False, html_message=html_message)
        
        return Response(
            {"message": "User registered successfully. Please check your email to confirm your registration."},
            status=status.HTTP_201_CREATED
        )
    

class ConfirmEmailView(View):
    def get(self, request, uid, token):
        # Retrieve the user based on uid.
        user = get_object_or_404(User, pk=uid)
        
        # Validate the token.
        if default_token_generator.check_token(user, token):
            # Activate the user account.
            user.is_active = True
            user.save()
            
            # Log the user in.
            login(request, user)
            
            # Redirect to your front-end home page.
            return HttpResponseRedirect("http://localhost:3000/")
        else:
            return HttpResponseBadRequest("Invalid or expired token.")
        
        
class LoginView(APIView):
    def post(self, request):
        # Get the username exactly as provided (do not convert to lower-case)
        username = request.data.get('username', '').strip()
        password = request.data.get('password')
        now = timezone.now()

        
        # --- Case-sensitive existence check ---
        try:
            user_obj = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "User does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Even if get() finds a record, it might be due to case-insensitive matching.
        # Check explicitly if the stored username matches exactly.
        if user_obj.username != username:
            return Response({"error": "User does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user_obj.is_active:
            return Response({"error": "User does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Retrieve the current lockout state using the provided username.
        attempts, block_count, lockout_until = get_lockout_info(username)

        # If the user is currently locked out, return a lockout error message.
        if lockout_until and now < lockout_until:
            remaining_seconds = (lockout_until - now).total_seconds()
            time_str = format_duration(remaining_seconds)
            return Response(
                {"error": f"Too many failed attempts. Please try again in {time_str}."},
                status=status.HTTP_400_BAD_REQUEST
            )


        # Attempt authentication using your custom backend that enforces case sensitivity.
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # On successful login, clear the lockout state.
            update_lockout_info(username, attempts=0, block_count=0, lockout_until=None)
            login(request, user)
            return Response({"message": "Logged in successfully."}, status=status.HTTP_200_OK)
        else:
            # Increment the failed attempt count.
            attempts += 1

            if attempts < FAILURE_LIMIT:
                update_lockout_info(username, attempts=attempts, block_count=block_count)
                return Response({"error": "Invalid credentials. Please try again."}, status=status.HTTP_400_BAD_REQUEST)
            else:
                # When the failure threshold is reached, increase block count and set lockout.
                block_count += 1

                if block_count in LOCK_TIME_LEVELS:
                    lock_duration = LOCK_TIME_LEVELS[block_count]
                else:
                    lock_duration = LOCK_TIME_LEVELS[3]

                lockout_until = now + lock_duration
                update_lockout_info(username, attempts=0, block_count=block_count, lockout_until=lockout_until)
                return Response(
                    {"error": f"Too many failed attempts. Your account is locked for {lock_duration}."},
                    status=status.HTTP_400_BAD_REQUEST
                )




# Custom logout view as an API endpoint
class LogoutView(APIView):
    def post(self, request):
        logout(request)  # This clears the session cookie
        return Response({"message": "Logged out successfully."},
                        status=status.HTTP_200_OK)
    


class AccountView(APIView):
    def get(self, request):
        if not request.user.is_authenticated:
            return Response({"error": "Not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
        
        user = request.user
        quizzes = Quiz.objects.filter(created_by=user, is_deleted=False)
        
        quizzes_data = []
        for quiz in quizzes:
            questions = Question.objects.filter(quiz=quiz)
            questions_data = [
                {
                    "question_id": q.pk,
                    "text": q.text,
                    "question_type": q.question_type,
                    "option_a": q.option_a,
                    "option_b": q.option_b,
                    "option_c": q.option_c,
                    "option_d": q.option_d,
                    "correct_answer": q.correct_answer,
                }
                for q in questions
            ]
            
            quizzes_data.append({
                "quiz_id": quiz.pk,
                "title": quiz.title,
                "language": quiz.language,
                "created_at": quiz.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "questions": questions_data,
            })
        
        data = {
            "user": {
                "username": user.username,
                "email": user.email,
            },
            "quizzes": quizzes_data,
        }
        return Response(data, status=status.HTTP_200_OK)

    
class SoftDeleteQuizView(APIView):
    def get_object(self, quiz_id):
        try:
            return Quiz.objects.get(pk=quiz_id)
        except Quiz.DoesNotExist:
            raise Http404("Quiz not found")

    def patch(self, request, *args, **kwargs):
     
        quiz_id = kwargs.get("quiz_id")
        if not quiz_id:
            return Response({"error": "No quiz_id provided."}, status=status.HTTP_400_BAD_REQUEST)

        # 1. EXAMPLE USE OF `request`: ensure user is authenticated or quiz is owned by request.user
        if not request.user.is_authenticated:
            return Response({"error": "Not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        quiz = self.get_object(quiz_id)
        if quiz.created_by != request.user:
            return Response({"error": "You do not own this quiz"}, status=status.HTTP_403_FORBIDDEN)

        # 2. EXAMPLE USE OF `*args`: let's just log them
        if args:
            logger.debug("Extra positional args passed to patch method:", args)

        # Soft-delete the quiz
        quiz.is_deleted = True
        quiz.save()

        return Response({"message": f"Quiz {quiz_id} soft-deleted successfully"}, status=status.HTTP_200_OK)


class SoftDeleteQuestionView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, question_id):
        try:
            return Question.objects.get(pk=question_id)
        except Question.DoesNotExist:
            raise Http404("Question not found")

    def patch(self, request, **kwargs):
        question_id = kwargs.get("question_id")
        if not question_id:
            return Response({"error": "No question_id provided."}, status=status.HTTP_400_BAD_REQUEST)

        if not request.user.is_authenticated:
            return Response({"error": "Not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        # Retrieve the question instance or return 404.
        question = self.get_object(question_id)

        # Check that the current user owns the quiz to which this question belongs.
        if question.quiz.created_by != request.user:
            return Response({"error": "You do not own this question."}, status=status.HTTP_403_FORBIDDEN)

        # Soft-delete the question.
        question.is_deleted = True
        try:
            question.save()
            return Response({"message": f"Question {question_id} soft-deleted successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



class QuizDetailView(APIView):
  
    def get(self, request, quiz_id):
        # Ensure that only quizzes created by the current user are fetched
        quiz = get_object_or_404(Quiz, pk=quiz_id, created_by=request.user, is_deleted=False)

        questions = quiz.questions.filter(is_deleted=False).order_by('display_order')
        
        # Build the original question data for editing
        questions_data = []
        for q in questions:
            questions_data.append({
            "question_id": q.pk,
            "text": q.text,
            "question_type": q.question_type,
            "option_a": q.option_a,
            "option_b": q.option_b,
            "option_c": q.option_c,
            "option_d": q.option_d,
            "correct_answer": q.correct_answer,
            "display_order": q.display_order,  # Use the new field here!
            "tf_option_true": getattr(q, "tf_option_true", None),
            "tf_option_false": getattr(q, "tf_option_false", None),
        })
        
        # Build arrays for display (used by QuizDisplay)
        questions_list = []
        alternatives_list = []
        answers_list = []
        question_types_list = []
        
        for q in questions:
            questions_list.append(q.text)
            question_types_list.append(q.question_type)
            
            if q.question_type == "MC":
                alternatives_list.append([
                    q.option_a,
                    q.option_b,
                    q.option_c,
                    q.option_d
                ])
            elif q.question_type == "TF":
                # Use custom fields if available; otherwise default:
                alternatives_list.append(["True", "False"])
            else:
                alternatives_list.append([])
            
            answers_list.append(q.correct_answer)
        
        # Determine quiz type: single-type or mixed
        question_types = {q.question_type for q in questions}
        if not questions:
            quiz_type_value = "multiple-choice"
        elif len(question_types) == 1:
            single_type = question_types.pop()  # 'MC', 'TF', or 'OE'
            if single_type == "MC":
                quiz_type_value = "multiple-choice"
            elif single_type == "TF":
                quiz_type_value = "true-false"
            else:
                quiz_type_value = "open-ended"
        else:
            quiz_type_value = "mixed"
        
        data = {
            "quiz_id": quiz.pk,
            "title": quiz.title,
            "language": quiz.language,
            "created_at": quiz.created_at.isoformat(),
            "quiz_type": quiz_type_value,
            "questions": questions_data,
            "display": {
                "questions": questions_list,
                "alternatives": alternatives_list,
                "answers": answers_list,
                "question_types": question_types_list,
            }
        }
        return Response(data, status=status.HTTP_200_OK)



class UpdateQuestionView(APIView):
    def put(self, request, question_id):
        # Retrieve the question instance or return 404
        question = get_object_or_404(Question, pk=question_id)
        
        # Extract fields from request.data (assumes JSON input)
        data = request.data
        
        
        # Update fields if provided; leave existing values if not
        question.text = data.get("text", question.text)
        question.question_type = data.get("question_type", question.question_type)
        question.option_a = data.get("option_a", question.option_a)
        question.option_b = data.get("option_b", question.option_b)
        question.option_c = data.get("option_c", question.option_c)
        question.option_d = data.get("option_d", question.option_d)
        
        # If it's TF, also update tf_option_true / tf_option_false
        if question.question_type == "TF":
            # If these new fields exist, store them; otherwise keep old ones
            question.tf_option_true = data.get("tf_option_true", question.tf_option_true)
            question.tf_option_false = data.get("tf_option_false", question.tf_option_false)

        # Retrieve the new correct answer (if provided)
        new_correct = data.get("correct_answer", question.correct_answer)
        
        if new_correct:
            current_qtype = question.question_type  # the updated question_type
            if current_qtype == "MC":
                # Valid answers for multiple-choice are a, b, c, or d.
                allowed = ['a', 'b', 'c', 'd']
                if new_correct.lower() not in allowed:
                    new_correct = 'a'
                else:
                    new_correct = new_correct.lower()
            elif current_qtype == "TF":
                # For TF, we'll unify correct_answer to "True" / "False"
                # (in case the client sends "true"/"false" or mixed)
                if new_correct.lower() == "true":
                    new_correct = "True"
                elif new_correct.lower() == "false":
                    new_correct = "False"
                else:
                    new_correct = "True"
        
        question.correct_answer = new_correct
        
        try:
            question.save()
            return Response({"message": "Question updated successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        


class BulkUpdateQuestionsView(APIView):
    def put(self, request):
        try:
            data = request.data
            questions_data = data.get("questions")
            if not questions_data or not isinstance(questions_data, list):
                return Response(
                    {"error": "Invalid payload format: expected a 'questions' key with a list of question updates."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            # Process each question update
            for item in questions_data:
                question_id = item.get("question_id")
                if not question_id:
                    continue  # or return an error if required
                question = get_object_or_404(Question, pk=question_id)
                
                # Update fields if provided.
                question.text = item.get("text", question.text)
                question.question_type = item.get("question_type", question.question_type)
                question.option_a = item.get("option_a", question.option_a)
                question.option_b = item.get("option_b", question.option_b)
                question.option_c = item.get("option_c", question.option_c)
                question.option_d = item.get("option_d", question.option_d)
                
                if question.question_type == "TF":
                    question.tf_option_true = item.get("tf_option_true", question.tf_option_true)
                    question.tf_option_false = item.get("tf_option_false", question.tf_option_false)
                
                # Process the new correct answer.
                new_correct = item.get("correct_answer", question.correct_answer)
                if new_correct:
                    current_qtype = question.question_type
                    if current_qtype == "MC":
                        allowed = ['a', 'b', 'c', 'd']
                        if new_correct.lower() not in allowed:
                            new_correct = 'a'
                        else:
                            new_correct = new_correct.lower()
                    elif current_qtype == "TF":
                        if new_correct.lower() == "true":
                            new_correct = "True"
                        elif new_correct.lower() == "false":
                            new_correct = "False"
                        else:
                            new_correct = "True"
                    # For open-ended, keep as is.
                question.correct_answer = new_correct

                # Save the updated question.
                question.save()
            
            return Response({"message": "Bulk update successful."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)



class BulkUpdateQuestionsOrderView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        updates = request.data.get("updates")
        if not updates or not isinstance(updates, list):
            return Response(
                {"error": "Invalid updates data. Provide a list of objects."},
                status=status.HTTP_400_BAD_REQUEST
            )

        for update in updates:
            question_id = update.get("question_id")
            # Use the correct key from your payload.
            new_order = update.get("display_order")
            if question_id is None or new_order is None:
                continue

            # Look up the question by its primary key.
            question = get_object_or_404(Question, pk=question_id, is_deleted=False)
            if question.quiz.created_by != request.user:
                return Response(
                    {"error": "You do not own this question."},
                    status=status.HTTP_403_FORBIDDEN
                )

            question.display_order = new_order
            question.save()

        return Response({"message": "Bulk update successful."}, status=status.HTTP_200_OK)


class GoogleSignupOrLoginView(APIView):
    @csrf_exempt
    def post(self, request,):
        token = request.data.get('token')
        try:
            # 1) Verify the token (ID token vs access token)
            parts = token.split('.')
            if len(parts) == 3:
                # ID token (JWT)
                idinfo = id_token.verify_oauth2_token(
                    token,
                    google_requests.Request(),
                    settings.GOOGLE_CLIENT_ID,
                    clock_skew_in_seconds=30
                )
            else:
                # Access token -> fetch userinfo endpoint
                resp = requests.get(
                    'https://www.googleapis.com/oauth2/v3/userinfo',
                    params={'access_token': token},
                    timeout=5
                )
                resp.raise_for_status()
                idinfo = resp.json()
                aud = idinfo.get('aud')
                if aud and aud != settings.GOOGLE_CLIENT_ID:
                    raise ValueError("Invalid audience in access token")

            email = idinfo['email']
            # derive a username
            first = idinfo.get('given_name') or idinfo.get('name', '').split()[0] or email

            # 2) Safely retrieve-or-create
            qs = User.objects.filter(email__iexact=email)
            if qs.exists():
                # if multiple, pick the oldest
                user = qs.order_by('id').first()
                created = False
            else:
                # no existing -> create one
                user = User.objects.create_user(
                    username=first,
                    email=email
                )
                user.first_name = first
                user.save()
                created = True

            # 3) Log them in
            login(request, user)

            return Response({
                'success': True,
                'created': created,
                'message': 'User logged in or created successfully'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # don’t expose internal stack traces in production
            return Response(
                {'error': f'Invalid Google token: {e}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        

class CheckAuthView(APIView):
    def get(self, request):
        if request.user.is_authenticated:
            return Response({'authenticated': True, 'username': request.user.username})
        else:
            return Response({'authenticated': False})
        

class ForgotPasswordView(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            if not email:
                return Response(
                    {"error": "Email is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            user = User.objects.filter(email=email).first()
            if not user:
                return Response(
                    {"error": "User with this email does not exist."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Check if the user has an empty password field or an unusable password.
            if not user.password or not user.has_usable_password():
                return Response(
                    {"error": "Your account is registered using Google authentication. Please log in using Google instead."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Generate a token and encode the user's ID.
            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Build a password reset URL.
            reset_link = f"{settings.FRONTEND_URL}/forgot-password/confirm/{uidb64}/{token}/"
            
            subject = "Password Reset Requested"
            message = (
                f"Hi {user.username},\n\n"
                "You recently requested a password reset for your account. "
                f"Please click the link below to reset your password:\n\n{reset_link}\n\n"
                "If you did not request this change, please ignore this email.\n\n"
                "Thank you."
            )
            
            # Send the email.
            send_mail(
                subject,
                message,
                settings.EMAIL_HOST_USER,  # From email address
                [email],
                fail_silently=True,
            )
            
            return Response({
                "message": "Password reset instructions sent.",
                "reset_link": reset_link
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "An internal error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ForgotPasswordConfirmView(APIView):
    def post(self, request):
        uidb64 = request.data.get('uidb64')
        token = request.data.get('token')
        new_password = request.data.get('new_password')
        
        if not (uidb64 and token and new_password):
            return Response({'error': 'Missing data.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_object_or_404(User, pk=uid)
        except Exception as e:
            return Response({'error': 'Invalid uid.'}, status=status.HTTP_400_BAD_REQUEST)
        
        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)
        


class BrowserLogView(APIView):

    http_method_names = ["post"]

    def post(self, request: HttpRequest, *args, **kwargs):
        try:
            data = json.loads(request.body.decode())
            logs = data.get("logs", [])

            # accept either string or list
            if isinstance(logs, str):
                logs = [logs]

            for entry in logs:
                frontend_logger.info("%s", entry)

            return JsonResponse({"ok": True})
        except Exception as exc:
            logging.getLogger(__name__).exception("Failed to write front‑log")
            return JsonResponse(
                {"ok": False, "error": str(exc)}, status=400
            )       