bool(os.getenv("MISTRAL_API_KEY")) and os.getenv("LLM_ENABLED", "true").lower() == "true"
