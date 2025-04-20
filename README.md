# Quiz AI (Django Backend)

A Django REST API that powers an AI‑driven quiz generator.  
It uses OpenAI (or your locally hosted scoring service) to generate and score multiple‑choice, true/false, and open‑ended quizzes. Users can register, log in (including Google OAuth), save quizzes to dashboards and take them with optional time limits, shuffle, review, and more.

---

## Features

- **AI‑Generated Quizzes**  
  - Multiple‑choice, True/False, Open‑ended  
  - Context‑aware or context‑free prompts  
  - Ensures varied, non‑repeating questions  

- **Quiz Management**  
  - Create/update/delete quizzes & questions  
  - Drag & drop reordering  
  - Soft‑delete support  

- **User Authentication**  
  - Username/password (case‑sensitive)  
  - Email confirmation & password reset  
  - Google OAuth signup/login  

- **Scoring & Feedback**  
  - Fuzzy/text/semantic scoring for open‑ended answers  
  - Forced scoring on time‑up  
  - Detailed per‑question feedback  

- **Logging**  
  - Backend logs (to `myapp.log`)  
  - Frontend logs endpoint (`/api/front-logs/`)  

---

## Quickstart

### 1. Clone & venv

```bash
git clone https://github.com/your-org/quiz-ai-backend.git
cd quiz-ai-backend
python3 -m venv .venv
source .venv/bin/activate       # macOS/Linux
.\.venv\Scripts\activate        # Windows PowerShell

pip install --upgrade pip
pip install -r requirements.txt
```
## create .env

# Django
SECRET_KEY=your-django-secret-key
DEBUG=True

# Database (PostgreSQL)
POSTGRES_DB=quiz_db
POSTGRES_USER=quiz_user
POSTGRES_PASSWORD=supersecret
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432

# OpenAI
OPENAI_API_KEY=sk-...

# Google OAuth
GOOGLE_CLIENT_ID=...

# Email (SMTP)
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=you@example.com
EMAIL_HOST_PASSWORD=emailpassword

# Frontend URL (for email links)
FRONTEND_URL=http://localhost:3000






# 5. Migrate & create superuser

python manage.py migrate
python manage.py createsuperuser




# 6. Run

python manage.py runserver

