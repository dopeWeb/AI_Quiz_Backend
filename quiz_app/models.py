from django.db import models
from django.contrib.auth.models import User

class Quiz(models.Model):
    title = models.CharField(max_length=200)
    language = models.CharField(max_length=20, default='English')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="quizzes")
    created_at = models.DateTimeField(auto_now_add=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.title

class Question(models.Model):
    QUESTION_TYPE_CHOICES = [
        ("MC", "Multiple Choice"),
        ("TF", "True/False"),
        ("OE", "Open Ended"),
    ]
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name="questions")
    text = models.TextField()
    question_type = models.CharField(max_length=2, choices=QUESTION_TYPE_CHOICES)
    option_a = models.CharField(max_length=255, blank=True, null=True)
    option_b = models.CharField(max_length=255, blank=True, null=True)
    option_c = models.CharField(max_length=255, blank=True, null=True)
    option_d = models.CharField(max_length=255, blank=True, null=True)
    tf_option_true = models.CharField(max_length=255, blank=True, null=True)
    tf_option_false = models.CharField(max_length=255, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    correct_answer = models.TextField(blank=True, null=True)
    display_order = models.IntegerField(default=0)  # renamed field


    def __str__(self):
        return self.text
