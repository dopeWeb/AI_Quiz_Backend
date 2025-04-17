import os
from typing import List
from django.conf import settings
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from .quiz_templates import (
    create_multiple_choice_template,
    create_true_false_template,
    create_open_ended_template,
)

# 1) Define your Pydantic models for structured output
class QuizTrueFalse(BaseModel):
    quiz_text: str = Field(description="The quiz text")
    questions: List[str] = Field(description="The quiz questions")
    answers: List[str] = Field(description="The quiz answers for each question as True or False only.")

class QuizMultipleChoice(BaseModel):
    quiz_text: str = Field(description="The quiz text")
    questions: List[str] = Field(description="The quiz questions")
    alternatives: List[List[str]] = Field(description="The quiz alternatives for each question")
    answers: List[str] = Field(description="The quiz answers")

class QuizOpenEnded(BaseModel):
    questions: List[str] = Field(description="The quiz questions")
    answers: List[str] = Field(description="The quiz answers")

# 2) Chain function to create the pipeline
def create_quiz_chain(prompt_template, llm, pydantic_object_schema):
    """
    Creates the chain for the quiz app using LangChain. 
    The pipe operator (|) merges a PromptTemplate with a 'structured output' parser.
    """
    return prompt_template | llm.with_structured_output(pydantic_object_schema)

# 3) Main function to generate quiz
def generate_quiz(
    openai_api_key: str,
    context: str,
    num_questions: int,
    quiz_type: str,
    language: str = "English"  # <--- new language param
):
    """
    Generate a quiz using the desired quiz_type
    (multiple-choice, true-false, open-ended) and requested language.
    """

    # 1. Ensure we have an OpenAI API key
    openai_api_key = settings.OPENAI_API_KEY
    if not openai_api_key:
        raise ValueError("OpenAI API key is not set in Django settings.")

    # 2. Set environment variable for LangChain
    os.environ["OPENAI_API_KEY"] = openai_api_key

    # 3. Initialize LLM with your local or remote GPT model
    llm = ChatOpenAI(
        model="gpt-4o-mini",  
        temperature=0.8,            
        top_p=0.9,                 
        frequency_penalty=0.7,      
        presence_penalty=0.8,       
)

    # 4. Select prompt template and Pydantic schema
    if quiz_type == "multiple-choice":
        prompt_template = create_multiple_choice_template(language)
        pydantic_object_schema = QuizMultipleChoice
    elif quiz_type == "true-false":
        prompt_template = create_true_false_template(language)
        pydantic_object_schema = QuizTrueFalse
    elif quiz_type == "open-ended":
        prompt_template = create_open_ended_template(language)
        pydantic_object_schema = QuizOpenEnded
    else:
        raise ValueError("Invalid quiz_type")

    # 5. Create the chain & invoke
    chain = create_quiz_chain(prompt_template, llm, pydantic_object_schema)
    quiz_response = chain.invoke({
        "num_questions": num_questions,
        "quiz_context": context
    })

    # 6. Return the raw Pydantic model
    return quiz_response
