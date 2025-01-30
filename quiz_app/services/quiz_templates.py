# quiz_app/services/quiz_templates.py

from langchain_core.prompts import ChatPromptTemplate

def create_multiple_choice_template(language: str = "English"):
    """
    Creates a multiple-choice prompt template that instructs GPT to write
    the quiz in the specified language, but without inserting 'a)' or 'b)'
    into the text of each choice. The correct answer should still be one of
    the letters: 'a', 'b', 'c', or 'd' in lowercase.
    """
    prompt = ChatPromptTemplate.from_messages([
        (
            'system',
            f"""You are a quiz engine that generates multiple-choice questions.
               The user will ask for a certain number of questions about a context.
               You must:

               1. Provide exactly {{num_questions}} questions in {language}.
               2. Each question must have four answer choices, but do not label them with letters or prefixes in the text. (Just list the text for each choice.)
               3. Return the correct answer separately as one of the letters: 'a', 'b', 'c', or 'd', in lowercase.
               4. All question text and choices must be in {language}.
               5. Do not include extra text or disclaimers.
            """
        ),
        (
            'human',
            f"""
            Please create a multiple-choice quiz with {{num_questions}} questions 
            about {{quiz_context}}, all in {language}.

            - Do NOT prepend letters like 'a)' or 'b)' to each choice's text.
            - Only indicate the correct answer as 'a', 'b', 'c', or 'd' in your final output.
            """
        )
    ])
    return prompt



def create_true_false_template(language: str = "English"):
    """
    Creates a true-false prompt template that instructs GPT to:
      - Write all question text in 'language'.
      - Use strictly 'True' or 'False' (in English) for the answers.
    """
    prompt = ChatPromptTemplate.from_messages([
        (
            'system',
            f"""You are a quiz engine that generates true-false questions according
               to user input specifications:
               1. Provide exactly {{num_questions}} questions in {language}.
               2. For each question, the correct answer must be strictly 'True' or 'False' in English.
               3. No extra commentary or disclaimers.
            """
        ),
        (
            'human',
            f"""Create EXACTLY {{num_questions}} true-false question(s) in {language} 
            about the following context:
            {{quiz_context}}

            IMPORTANT:
            - All question text must be in {language}.
            - Each correct answer must be either 'True' or 'False' (in English).
            """
        )
    ])
    return prompt



def create_open_ended_template(language: str = "English"):
    """
    Creates an open-ended prompt template that instructs GPT to write
    the quiz in the specified language.
    """
    prompt = ChatPromptTemplate.from_messages([
        (
            'system',
            f"""You are a quiz engine that generates open-ended questions with answers
               according to user input specifications.
               1. Provide exactly {{num_questions}} open-ended questions in {language}.
               2. Provide an answer for each question in {language}.
               3. No additional commentary or disclaimers.
            """
        ),
        (
            'human',
            f"""Create a quiz with {{num_questions}} open-ended questions about the following context:
            {{quiz_context}}

            Write both the questions and answers in {language}.
            """
        )
    ])
    return prompt
