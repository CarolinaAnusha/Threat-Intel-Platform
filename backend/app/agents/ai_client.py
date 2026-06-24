import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()


class AIClient:
    def __init__(self):
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")

    def generate_json(self, system_prompt: str, user_prompt: str):
        if self.groq_api_key:
            try:
                return self._call_groq(system_prompt, user_prompt)
            except Exception as error:
                print(f"Groq failed, falling back. Error: {error}")

        if self.openai_api_key:
            try:
                return self._call_openai(system_prompt, user_prompt)
            except Exception as error:
                print(f"OpenAI failed, falling back. Error: {error}")

        return None

    def _call_groq(self, system_prompt: str, user_prompt: str):
        url = "https://api.groq.com/openai/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": "llama-3.1-70b-versatile",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"]
        return json.loads(content)

    def _call_openai(self, system_prompt: str, user_prompt: str):
        url = "https://api.openai.com/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        response = requests.post(url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"]
        return json.loads(content)