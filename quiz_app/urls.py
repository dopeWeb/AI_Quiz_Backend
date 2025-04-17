from django.urls import path
from .views import (
    BrowserLogView,
    BulkUpdateQuestionsOrderView,
    BulkUpdateQuestionsView,
    CheckAuthView,
    ConfirmEmailView,
    ForgotPasswordConfirmView,
    ForgotPasswordView,
    GenerateQuizView,
    ScoreQuizView,
    SaveQuizView,        # Added save view
    RegisterView,
    LoginView,
    LogoutView,
    AccountView,
    SoftDeleteQuestionView,
    SoftDeleteQuizView,
    QuizDetailView,
    UpdateQuestionView,
    GoogleSignupOrLoginView,
)
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('quiz', GenerateQuizView.as_view(), name='generate_quiz'),
    path('quiz/score', ScoreQuizView.as_view(), name='score_quiz'),
    path('quiz/save/', SaveQuizView.as_view(), name='save_quiz'),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('account/', AccountView.as_view(), name='account'),
    path('quizzes/<int:quiz_id>/softdelete', SoftDeleteQuizView.as_view(), name='soft_delete_quiz'),
    path('questions/<int:question_id>/softdelete/', SoftDeleteQuestionView.as_view(), name='soft_delete_question'),
    path('quizzes/<int:quiz_id>', QuizDetailView.as_view(), name='quiz_detail'),
    path('questions/<int:question_id>/update/', UpdateQuestionView.as_view(), name='update_question'),
    path('google-signup-or-login/', GoogleSignupOrLoginView.as_view(), name='google-signup-or-login'),
    path('check-auth/', CheckAuthView.as_view(), name='check-auth'),
    path('questions/bulk_update/', BulkUpdateQuestionsView.as_view(), name='bulk-update'),
    path('questions/bulk_update_order/', BulkUpdateQuestionsOrderView.as_view(), name='bulk-update-order'),
    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('auth/password-reset-confirm/', ForgotPasswordConfirmView.as_view(), name='password-reset-confirm'),
    path('confirm-email/<int:uid>/<str:token>/', ConfirmEmailView.as_view(), name='confirm_email'),
    path("front-logs/", BrowserLogView.as_view(), name="browser-log"),






    
]

