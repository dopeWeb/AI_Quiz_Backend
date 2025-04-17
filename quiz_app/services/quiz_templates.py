from langchain_core.prompts import ChatPromptTemplate

def create_multiple_choice_template(language: str = "English"):
    prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        # {language} is inlined; {num_questions}/{quiz_context} remain template vars
        f"Your task is to generate a multiple-choice quiz in {language}. "
        "For each question, provide exactly four answer choices without any letter labels in the text. "
        "Then, return the correct answer as one of the letters: A, B, C, or D (in uppercase). "
        "All content (questions and choices) must be written in {{language}}. "              # note the double braces
        "If a non‑empty context ({quiz_context}) is provided, each question must probe a different facet "
        "(e.g., definitions, advantages, limitations, applications) so no two overlap. "
        "If the context is empty, select {num_questions} entirely distinct domains "
        "(e.g., history, science, arts, geography, technology), and phrase each question and its choices "
        "in a brand‑new way—never recycle wording across runs unless absolutely no new option remains."
    ),
    (
        "human",
        # {num_questions}/{quiz_context} are still template vars; {language} is inlined
        f"Please create a quiz with {{num_questions}} questions based on the following context: {{quiz_context}}. "
        "Ensure every question has exactly four answer choices and specify the correct answer as a single uppercase letter (A, B, C, or D). "
        "Use fresh, varied phrasing for both questions and choices—do not repeat wording from any previous quiz generation. "
        "All output should be in {{language}}."                                           # and here too
    ),
    ])
    
    return prompt



def create_true_false_template(language: str = "English"):
    prompt = ChatPromptTemplate.from_messages([
          (
            "system",
            # {language} is inlined; {num_questions} & {quiz_context} remain template vars
            f"You are a quiz engine generating true–false statements and answers in {language}. "
            "Produce exactly {num_questions} distinct question–answer pairs. "
            "If a non‑empty context ({quiz_context}) is given, each statement must address a different aspect "
            "(e.g. definitions, advantages, limitations, applications, examples, historical facts) so that no two "
            "overlap in content. If the context is empty, choose {num_questions} entirely separate topics "
            "(science, history, arts, technology, geography, etc.). "
            "Always vary your wording and structure—never repeat phrasing across runs unless you’ve truly exhausted "
            "all unique possibilities."
        ),
        (
            "human",
            # single f‑string so {num_questions} & {quiz_context} are still template vars
            f"Create a quiz with {{num_questions}} true–false statements about: {{quiz_context}}. "
            f"Write exactly {{num_questions}} statements and their correct answers ('True' or 'False') in {language}, "
            "using fresh wording and no extra commentary or explanations."
        ),
    ])
    return prompt


def create_open_ended_template(language: str = "English"):
    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            # {language} is injected; {num_questions}/{quiz_context} stay as template vars
            f"You are a quiz engine generating open‑ended questions and answers in {language}. "
            "Produce exactly {num_questions} question‑answer pairs. "
            "If a non‑empty context ({quiz_context}) is supplied, each question must explore a distinct facet "
            "(e.g. definition, benefits, drawbacks, use‑cases, examples, future directions) so that no two "
            "questions overlap. If the context is empty, select entirely different domains "
            "(history, science, arts, philosophy, geography, etc.) AND different question types "
            "(explanation, comparison, analysis, evaluation), using fresh wording each time. "
            "Only repeat a topic or phrasing if absolutely no new question remains. "
            "Even when asked multiple times on the same context, always vary the angle and wording so you never"
            " produce the identical question twice."
        ),
        (
            "human",
            # runtime will fill in both num_questions and quiz_context (which may be "")
            "Create a quiz with {num_questions} open‑ended questions about: {quiz_context}. "
            f"Write each question and its answer in {language}, with no extra commentary or disclaimers."
        ),
    ])
    return prompt