def evaluate_rag_response(context, response):
    """
    Evaluate RAG response using the specified Value and Rationale prompts.
    """
    evaluation_prompt = f"""
    Context: {context}
    Response: {response}

    Evaluate the response based on these criteria:
    - TP: Response fully and accurately reflects context information
    - FP: Response contains inaccurate/incorrect information not in context
    - FN: Response omits information present in context

    """

    def analyze_response(context, response):
        # Convert to sets of meaningful phrases rather than individual words
        context_phrases = set([phrase.strip() for phrase in context.lower().split('.')])
        response_phrases = set([phrase.strip() for phrase in response.lower().split('.')])

        # Check for information accuracy and completeness
        incorrect_info = any(phrase not in context_phrases for phrase in response_phrases)
        missing_info = any(phrase not in response_phrases for phrase in context_phrases)

        if not incorrect_info and not missing_info:
            return "TP", "The response fully and accurately reflects the context information, maintaining complete provenance."
        elif incorrect_info:
            return "FP", "The response contains information not supported by the original context, violating provenance."
        else:
            return "FN", "The response omits critical information present in the context, affecting completeness."

    value, rationale = analyze_response(context, response)

    return {
        "Value": value,
        "Rationale": rationale,
        "Context": context,
        "Response": response
    }